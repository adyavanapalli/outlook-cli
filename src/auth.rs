//! Authentication orchestration: token reuse, renewal, and unattended sign-in.

use crate::oauth;
use crate::output::outln;
use crate::owa::{self, OwaError};
use crate::session::{AuthState, Config, SessionFile, Store, now_epoch};
use crate::unattended;
use anyhow::Context;
use chrono::{DateTime, Utc};

const UNATTENDED_RETRY_DELAY_SECONDS: i64 = 30 * 60;

trait AuthOperations {
    fn access_is_valid(&self, auth: &AuthState) -> bool;
    fn refresh_access_token(
        &self,
        auth: &mut AuthState,
        configured_username: Option<&str>,
    ) -> anyhow::Result<()>;
    fn renew_from_microsoft_session(
        &self,
        auth: &mut AuthState,
        configured_username: Option<&str>,
    ) -> anyhow::Result<()>;
    fn unattended_login(&self, config: &Config) -> anyhow::Result<AuthState>;
}

struct LiveAuthOperations;

impl AuthOperations for LiveAuthOperations {
    fn access_is_valid(&self, auth: &AuthState) -> bool {
        oauth::access_is_valid(auth)
    }

    fn refresh_access_token(
        &self,
        auth: &mut AuthState,
        configured_username: Option<&str>,
    ) -> anyhow::Result<()> {
        oauth::refresh_access_token(auth, configured_username)
    }

    fn renew_from_microsoft_session(
        &self,
        auth: &mut AuthState,
        configured_username: Option<&str>,
    ) -> anyhow::Result<()> {
        oauth::renew_from_microsoft_session(auth, configured_username)
    }

    fn unattended_login(&self, config: &Config) -> anyhow::Result<AuthState> {
        unattended::login(config)
    }
}

pub fn login(store: &Store) -> anyhow::Result<()> {
    let _session_lock = store.acquire_session_lock()?;
    let mut session = store.load()?;
    if !oauth::access_is_valid(&session.auth) {
        ensure_access(store, &mut session, true)?;
        store.save(&session)?;
    }

    outln!("Logged in.")?;
    if let Some(username) = session.config.username.as_deref() {
        outln!("  username: {username}")?;
    }
    for (label, expires_at) in expirations(&session.auth) {
        print_expiry(label, expires_at)?;
    }
    Ok(())
}

pub fn ensure_access(
    store: &Store,
    session: &mut SessionFile,
    bypass_unattended_backoff: bool,
) -> anyhow::Result<()> {
    ensure_access_with(
        store,
        session,
        bypass_unattended_backoff,
        now_epoch(),
        &LiveAuthOperations,
    )
}

fn ensure_access_with<O: AuthOperations>(
    store: &Store,
    session: &mut SessionFile,
    bypass_unattended_backoff: bool,
    now: i64,
    operations: &O,
) -> anyhow::Result<()> {
    if operations.access_is_valid(&session.auth) {
        return Ok(());
    }

    let mut renewal_failures = Vec::new();
    if session
        .auth
        .refresh_token
        .as_ref()
        .is_some_and(|token| token.is_valid_at(now, 0))
    {
        match operations.refresh_access_token(&mut session.auth, session.config.username.as_deref())
        {
            Ok(()) if operations.access_is_valid(&session.auth) => return Ok(()),
            Ok(()) => renewal_failures
                .push("refresh-token renewal returned no usable access token".to_string()),
            Err(error) => renewal_failures.push(format!("refresh-token renewal failed: {error:#}")),
        }
    }

    if session
        .auth
        .microsoft_session
        .as_ref()
        .is_some_and(|value| value.is_valid_at(now))
    {
        match operations
            .renew_from_microsoft_session(&mut session.auth, session.config.username.as_deref())
        {
            Ok(()) if operations.access_is_valid(&session.auth) => return Ok(()),
            Ok(()) => renewal_failures
                .push("Microsoft-session renewal returned no usable access token".to_string()),
            Err(error) => {
                renewal_failures.push(format!("Microsoft-session renewal failed: {error:#}"));
            }
        }
    }

    match perform_unattended_login(store, session, bypass_unattended_backoff, now, operations) {
        Ok(()) => Ok(()),
        Err(error) if renewal_failures.is_empty() => {
            Err(error).context("unattended Microsoft login failed")
        }
        Err(error) => Err(error).context(format!(
            "unattended Microsoft login failed after token renewal attempts also failed: {}",
            renewal_failures.join("; ")
        )),
    }
}

fn perform_unattended_login<O: AuthOperations>(
    store: &Store,
    session: &mut SessionFile,
    bypass_backoff: bool,
    now: i64,
    operations: &O,
) -> anyhow::Result<()> {
    if !bypass_backoff
        && let Some(previous) = session.auth.last_unattended_attempt_at
        && let Some(remaining) = unattended_backoff_remaining(previous, now)
    {
        anyhow::bail!(
            "unattended login is rate-limited for another {remaining} seconds; run `outlook auth login` to retry explicitly"
        );
    }

    session.auth.last_unattended_attempt_at = Some(now);
    store
        .save(session)
        .context("cannot record unattended login attempt")?;
    let mut auth = operations.unattended_login(&session.config)?;
    if !operations.access_is_valid(&auth) {
        anyhow::bail!("unattended login returned no usable access token");
    }
    let persistent_session = auth.microsoft_session.is_some();
    auth.last_unattended_attempt_at = Some(now);
    session.auth = auth;
    store
        .save(session)
        .context("cannot persist unattended login authentication")?;
    if !persistent_session {
        eprintln!(
            "warning: Microsoft did not issue a persistent stay-signed-in cookie; unattended login may be needed again when the refresh token expires"
        );
    }
    Ok(())
}

fn unattended_backoff_remaining(previous: i64, now: i64) -> Option<i64> {
    let retry_at = previous.saturating_add(UNATTENDED_RETRY_DELAY_SECONDS);
    (retry_at > now).then(|| retry_at.saturating_sub(now))
}

pub fn ensure_bootstrap(store: &Store, session: &mut SessionFile) -> anyhow::Result<()> {
    if session.auth.calendar_id.is_some() {
        return Ok(());
    }
    let mut result = owa::get_bootstrap(&session.auth);
    if matches!(result, Err(OwaError::Unauthorized)) {
        if let Some(token) = session.auth.access_token.as_mut() {
            token.expires_at = 0;
        }
        ensure_access(store, session, false)?;
        result = owa::get_bootstrap(&session.auth);
    }
    session.auth.calendar_id = Some(result.map_err(anyhow::Error::new)?);
    Ok(())
}

pub fn logout(store: &Store) -> anyhow::Result<()> {
    let _session_lock = store.acquire_session_lock()?;
    let mut session = store.load()?;
    session.auth.clear();
    store.save(&session)?;
    outln!("Logged out locally. Configuration was preserved.")
}

pub fn status(store: &Store) -> anyhow::Result<()> {
    let session = store.load()?;
    let logged_in = session.auth.has_any_credentials();
    outln!(
        "{}",
        if logged_in {
            "logged in (local session present)"
        } else {
            "not logged in"
        }
    )?;
    if logged_in && let Some(username) = session.config.username.as_deref() {
        outln!("  username: {username}")?;
    }
    if let Some(attempt) = session.auth.last_unattended_attempt_at.and_then(timestamp) {
        outln!("  last unattended attempt: {}", attempt.to_rfc3339())?;
    }
    if logged_in {
        for (label, expires_at) in expirations(&session.auth) {
            print_token_status(label, expires_at)?;
        }
    }
    outln!("  session file: {}", store.path().display())
}

fn expirations(auth: &AuthState) -> [(&'static str, Option<i64>); 3] {
    [
        (
            "access token",
            auth.access_token.as_ref().map(|token| token.expires_at),
        ),
        (
            "refresh token",
            auth.refresh_token.as_ref().map(|token| token.expires_at),
        ),
        (
            "Microsoft session",
            auth.microsoft_session
                .as_ref()
                .map(|value| value.expires_at),
        ),
    ]
}

fn print_expiry(label: &str, expires_at: Option<i64>) -> anyhow::Result<()> {
    expires_at.and_then(timestamp).map_or_else(
        || outln!("  {label}: unavailable"),
        |value| outln!("  {label} expires: {}", value.to_rfc3339()),
    )
}

fn print_token_status(label: &str, expires_at: Option<i64>) -> anyhow::Result<()> {
    let now = now_epoch();
    match expires_at {
        Some(expiry) if expiry > now => {
            let formatted =
                timestamp(expiry).map_or_else(|| expiry.to_string(), |value| value.to_rfc3339());
            outln!(
                "  {label}: valid (expires {formatted}, in {}s)",
                expiry.saturating_sub(now)
            )
        }
        Some(expiry) => outln!("  {label}: expired {}s ago", now.saturating_sub(expiry)),
        None => outln!("  {label}: absent"),
    }
}

const fn timestamp(value: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
}

#[cfg(test)]
mod tests {
    use super::{AuthOperations, ensure_access_with, unattended_backoff_remaining};
    use crate::session::{
        AuthState, Config, MicrosoftSession, SessionFile, Store, StoredCookie, Token,
    };
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Copy, Clone)]
    enum Outcome {
        Success,
        SuccessWithoutAccess,
        Failure(&'static str),
    }

    struct FakeAuthOperations {
        refresh: Outcome,
        microsoft_session: Outcome,
        unattended: Outcome,
        calls: RefCell<Vec<&'static str>>,
    }

    impl FakeAuthOperations {
        fn new(refresh: Outcome, microsoft_session: Outcome, unattended: Outcome) -> Self {
            Self {
                refresh,
                microsoft_session,
                unattended,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl AuthOperations for FakeAuthOperations {
        fn access_is_valid(&self, auth: &AuthState) -> bool {
            auth.access_token
                .as_ref()
                .is_some_and(|token| token.value == "usable-access")
        }

        fn refresh_access_token(
            &self,
            auth: &mut AuthState,
            _configured_username: Option<&str>,
        ) -> anyhow::Result<()> {
            self.calls.borrow_mut().push("refresh");
            apply_outcome(self.refresh, auth)
        }

        fn renew_from_microsoft_session(
            &self,
            auth: &mut AuthState,
            _configured_username: Option<&str>,
        ) -> anyhow::Result<()> {
            self.calls.borrow_mut().push("microsoft-session");
            apply_outcome(self.microsoft_session, auth)
        }

        fn unattended_login(&self, _config: &Config) -> anyhow::Result<AuthState> {
            self.calls.borrow_mut().push("unattended");
            match self.unattended {
                Outcome::Success => Ok(auth_with_usable_access()),
                Outcome::SuccessWithoutAccess => Ok(AuthState::default()),
                Outcome::Failure(message) => Err(anyhow::anyhow!(message)),
            }
        }
    }

    fn apply_outcome(outcome: Outcome, auth: &mut AuthState) -> anyhow::Result<()> {
        match outcome {
            Outcome::Success => {
                auth.access_token = auth_with_usable_access().access_token;
                Ok(())
            }
            Outcome::SuccessWithoutAccess => Ok(()),
            Outcome::Failure(message) => Err(anyhow::anyhow!(message)),
        }
    }

    fn auth_with_usable_access() -> AuthState {
        AuthState {
            access_token: Some(Token {
                value: "usable-access".into(),
                expires_at: 200,
                issued_at: Some(100),
            }),
            ..AuthState::default()
        }
    }

    fn session_with_renewal_options() -> SessionFile {
        let mut session = SessionFile::default();
        session.auth.refresh_token = Some(Token {
            value: "refresh".into(),
            expires_at: 200,
            issued_at: Some(50),
        });
        session.auth.microsoft_session = Some(MicrosoftSession {
            cookies: BTreeMap::from([(
                "ESTSAUTHPERSISTENT".into(),
                StoredCookie {
                    value: "cookie".into(),
                    domain: ".login.microsoftonline.com".into(),
                    path: "/".into(),
                    expires_at: 200,
                },
            )]),
            expires_at: 200,
        });
        session
    }

    #[test]
    fn valid_access_short_circuits_all_renewal_methods() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("session.json"));
        let mut session = SessionFile {
            auth: auth_with_usable_access(),
            ..SessionFile::default()
        };
        let operations = FakeAuthOperations::new(
            Outcome::Failure("refresh should not run"),
            Outcome::Failure("session renewal should not run"),
            Outcome::Failure("unattended should not run"),
        );

        ensure_access_with(&store, &mut session, false, 100, &operations).unwrap();

        assert!(operations.calls.borrow().is_empty());
    }

    #[test]
    fn failed_renewals_are_retained_in_the_final_error() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("session.json"));
        let mut session = session_with_renewal_options();
        let operations = FakeAuthOperations::new(
            Outcome::Failure("refresh rejected"),
            Outcome::Failure("persistent session rejected"),
            Outcome::Failure("interactive login rejected"),
        );

        let error = ensure_access_with(&store, &mut session, true, 100, &operations).unwrap_err();
        let message = format!("{error:#}");

        assert_eq!(
            operations.calls.into_inner(),
            ["refresh", "microsoft-session", "unattended"]
        );
        for expected in [
            "refresh-token renewal failed: refresh rejected",
            "Microsoft-session renewal failed: persistent session rejected",
            "interactive login rejected",
        ] {
            assert!(
                message.contains(expected),
                "missing {expected:?} in {message:?}"
            );
        }
        assert_eq!(
            store.load().unwrap().auth.last_unattended_attempt_at,
            Some(100)
        );
    }

    #[test]
    fn renewal_success_must_produce_a_usable_access_token() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("session.json"));
        let mut session = session_with_renewal_options();
        let operations = FakeAuthOperations::new(
            Outcome::SuccessWithoutAccess,
            Outcome::Success,
            Outcome::Failure("unattended should not run"),
        );

        ensure_access_with(&store, &mut session, false, 100, &operations).unwrap();

        assert_eq!(
            operations.calls.into_inner(),
            ["refresh", "microsoft-session"]
        );
        assert_eq!(
            session
                .auth
                .access_token
                .as_ref()
                .map(|token| token.value.as_str()),
            Some("usable-access")
        );
    }

    #[test]
    fn invalid_unattended_result_does_not_replace_existing_authentication() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("session.json"));
        let mut session = SessionFile::default();
        session.auth.access_token = Some(Token {
            value: "expired-access".into(),
            expires_at: 0,
            issued_at: None,
        });
        let operations = FakeAuthOperations::new(
            Outcome::Failure("refresh should not run"),
            Outcome::Failure("session renewal should not run"),
            Outcome::SuccessWithoutAccess,
        );

        let error = ensure_access_with(&store, &mut session, true, 100, &operations).unwrap_err();

        assert!(format!("{error:#}").contains("returned no usable access token"));
        assert_eq!(
            session
                .auth
                .access_token
                .as_ref()
                .map(|token| token.value.as_str()),
            Some("expired-access")
        );
        let persisted = store.load().unwrap();
        assert_eq!(persisted.auth.last_unattended_attempt_at, Some(100));
        assert_eq!(
            persisted
                .auth
                .access_token
                .as_ref()
                .map(|token| token.value.as_str()),
            Some("expired-access")
        );
    }

    #[test]
    fn unattended_success_is_persisted_with_the_attempt_time() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("session.json"));
        let mut session = SessionFile::default();
        let operations = FakeAuthOperations::new(
            Outcome::Failure("refresh should not run"),
            Outcome::Failure("session renewal should not run"),
            Outcome::Success,
        );

        ensure_access_with(&store, &mut session, true, 100, &operations).unwrap();

        assert_eq!(session.auth.last_unattended_attempt_at, Some(100));
        let persisted = store.load().unwrap();
        assert_eq!(persisted.auth.last_unattended_attempt_at, Some(100));
        assert_eq!(
            persisted
                .auth
                .access_token
                .as_ref()
                .map(|token| token.value.as_str()),
            Some("usable-access")
        );
    }

    #[test]
    fn backoff_boundaries_do_not_overflow_on_persisted_timestamps() {
        assert_eq!(unattended_backoff_remaining(100, 1_899), Some(1));
        assert_eq!(unattended_backoff_remaining(100, 1_900), None);
        assert_eq!(
            unattended_backoff_remaining(i64::MAX, i64::MIN),
            Some(i64::MAX)
        );
    }
}

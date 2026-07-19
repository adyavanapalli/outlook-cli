//! `outlook config` commands.

use crate::output::{self, outln};
use crate::session::{Config, SessionFile, Store, Token};
use clap::ValueEnum;
use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ConfigKey {
    Username,
    Password,
    AuthenticatorKey,
    ChromeBinary,
    Timezone,
}

impl ConfigKey {
    const fn name(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::AuthenticatorKey => "authenticator-key",
            Self::ChromeBinary => "chrome-binary",
            Self::Timezone => "timezone",
        }
    }
}

pub fn get(store: &Store, key: Option<ConfigKey>, show_secrets: bool) -> anyhow::Result<()> {
    let session = store.load()?;
    if let Some(key) = key {
        let value = value_for_key(&session.config, key, show_secrets);
        value.map_or_else(|| outln!("<unset>"), |value| outln!("{value}"))?;
        return Ok(());
    }
    let value = if show_secrets {
        serde_json::to_value(&session)?
    } else {
        redacted_session(&session)
    };
    output::json(&value)
}

pub fn set(store: &Store, key: ConfigKey, value: Option<String>) -> anyhow::Result<()> {
    let _session_lock = store.acquire_session_lock()?;
    let mut session = store.load()?;
    let value = match (key, value) {
        (ConfigKey::Password, None) => rpassword::prompt_password("Password: ")?,
        (ConfigKey::AuthenticatorKey, None) => {
            rpassword::prompt_password("Authenticator key or TOTP URI: ")?
        }
        (_, Some(value)) => value,
        (_, None) => prompt(&format!("{}: ", key.name()))?,
    };
    match key {
        ConfigKey::Username => {
            let username = nonempty(&value);
            let changed = match (session.config.username.as_deref(), username.as_deref()) {
                (Some(current), Some(updated)) => !current.eq_ignore_ascii_case(updated),
                (None, None) => false,
                _ => true,
            };
            session.config.username = username;
            if changed {
                session.auth.clear();
            }
        }
        ConfigKey::Password => {
            session.config.password = (!value.is_empty()).then_some(value);
        }
        ConfigKey::AuthenticatorKey => session.config.authenticator_key = nonempty(&value),
        ConfigKey::ChromeBinary => {
            session.config.chrome_binary = nonempty(&value).map(|value| expand_home(&value));
        }
        ConfigKey::Timezone => {
            if value.trim().is_empty() {
                anyhow::bail!("timezone cannot be empty");
            }
            session.config.timezone = value.trim().to_string();
        }
    }
    if matches!(
        key,
        ConfigKey::Username
            | ConfigKey::Password
            | ConfigKey::AuthenticatorKey
            | ConfigKey::ChromeBinary
    ) {
        session.auth.last_unattended_attempt_at = None;
    }
    store.save(&session)?;
    outln!("{} updated.", key.name())
}

fn value_for_key(config: &Config, key: ConfigKey, show_secrets: bool) -> Option<String> {
    match key {
        ConfigKey::Username => config.username.clone(),
        ConfigKey::Password => config
            .password
            .as_deref()
            .map(|value| secret_value(value, show_secrets)),
        ConfigKey::AuthenticatorKey => config
            .authenticator_key
            .as_deref()
            .map(|value| secret_value(value, show_secrets)),
        ConfigKey::ChromeBinary => config
            .chrome_binary
            .as_ref()
            .map(|path| path.display().to_string()),
        ConfigKey::Timezone => Some(config.timezone.clone()),
    }
}

fn redacted_session(session: &SessionFile) -> Value {
    let auth = &session.auth;
    json!({
        "version": session.version,
        "config": {
            "username": session.config.username,
            "password": session.config.password.as_ref().map(|_| "<redacted>"),
            "authenticator_key": session.config.authenticator_key.as_ref().map(|_| "<redacted>"),
            "chrome_binary": session.config.chrome_binary,
            "timezone": session.config.timezone,
        },
        "auth": {
            "access_token": auth.access_token.as_ref().map(redacted_token),
            "refresh_token": auth.refresh_token.as_ref().map(redacted_token),
            "microsoft_session": auth.microsoft_session.as_ref().map(|session| json!({
                "cookies": session.cookies.keys().collect::<Vec<_>>(),
                "expires_at": session.expires_at,
            })),
            "home_account_id": auth.home_account_id,
            "tenant_id": auth.tenant_id,
            "anchor_mailbox": auth.anchor_mailbox,
            "client_version": auth.client_version,
            "calendar_id": auth.calendar_id,
            "last_unattended_attempt_at": auth.last_unattended_attempt_at,
        }
    })
}

fn secret_value(value: &str, show: bool) -> String {
    if show {
        value.to_string()
    } else {
        "<configured; use --show-secrets to display>".to_string()
    }
}

fn redacted_token(token: &Token) -> Value {
    json!({
        "value": "<redacted>",
        "expires_at": token.expires_at,
        "issued_at": token.issued_at,
    })
}

fn nonempty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn prompt(message: &str) -> anyhow::Result<String> {
    eprint!("{message}");
    std::io::stderr().flush().ok();
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

fn expand_home(value: &str) -> PathBuf {
    if value == "~" {
        return std::env::var_os("HOME").map_or_else(|| PathBuf::from(value), PathBuf::from);
    }
    if let Some(rest) = value.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::{ConfigKey, expand_home, redacted_session, value_for_key};
    use crate::session::{Config, SessionFile, Token};

    #[test]
    fn secrets_are_redacted_by_default() {
        let config = Config {
            password: Some("password-secret".into()),
            authenticator_key: Some("base32-secret".into()),
            ..Config::default()
        };
        assert_eq!(
            value_for_key(&config, ConfigKey::Password, false).as_deref(),
            Some("<configured; use --show-secrets to display>")
        );
        assert_eq!(
            value_for_key(&config, ConfigKey::Password, true).as_deref(),
            Some("password-secret")
        );
        assert_eq!(
            value_for_key(&config, ConfigKey::AuthenticatorKey, false).as_deref(),
            Some("<configured; use --show-secrets to display>")
        );
        assert_eq!(
            value_for_key(&config, ConfigKey::AuthenticatorKey, true).as_deref(),
            Some("base32-secret")
        );
    }

    #[test]
    fn account_identifiers_are_not_redacted() {
        let mut session = SessionFile::default();
        session.auth.home_account_id = Some("home-id".into());
        session.auth.anchor_mailbox = Some("anchor-id".into());
        session.auth.calendar_id = Some("calendar-id".into());
        session.auth.access_token = Some(Token {
            value: "bearer-secret".into(),
            expires_at: 42,
            issued_at: None,
        });
        let value = redacted_session(&session);
        assert_eq!(value["auth"]["home_account_id"], "home-id");
        assert_eq!(value["auth"]["anchor_mailbox"], "anchor-id");
        assert_eq!(value["auth"]["calendar_id"], "calendar-id");
        assert_eq!(value["auth"]["access_token"]["value"], "<redacted>");
    }

    #[test]
    fn non_home_paths_are_unchanged() {
        assert_eq!(
            expand_home("/tmp/profile"),
            std::path::Path::new("/tmp/profile")
        );
    }
}

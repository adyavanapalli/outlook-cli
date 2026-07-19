//! Owner-only configuration and authentication state.

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const CURRENT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct SessionFile {
    pub version: u32,
    #[serde(default)]
    pub config: Config,
    #[serde(default)]
    pub auth: AuthState,
}

impl Default for SessionFile {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            config: Config::default(),
            auth: AuthState::default(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(
        default,
        alias = "totp_secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chrome_binary: Option<PathBuf>,
    #[serde(
        default = "crate::timezone::system_exchange_timezone",
        alias = "time_zone"
    )]
    pub timezone: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            authenticator_key: None,
            chrome_binary: None,
            timezone: crate::timezone::system_exchange_timezone(),
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct AuthState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<Token>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Token>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub microsoft_session: Option<MicrosoftSession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_mailbox: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_unattended_attempt_at: Option<i64>,
}

impl AuthState {
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub const fn has_any_credentials(&self) -> bool {
        self.access_token.is_some()
            || self.refresh_token.is_some()
            || self.microsoft_session.is_some()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    pub value: String,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
}

impl Token {
    pub const fn is_valid_at(&self, now: i64, skew_seconds: i64) -> bool {
        !self.value.is_empty() && self.expires_at > now + skew_seconds
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct MicrosoftSession {
    pub cookies: BTreeMap<String, StoredCookie>,
    pub expires_at: i64,
}

impl MicrosoftSession {
    pub fn is_valid_at(&self, now: i64) -> bool {
        !self.cookies.is_empty() && self.expires_at > now
    }
}

#[derive(Serialize, Deserialize)]
pub struct StoredCookie {
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires_at: i64,
}

pub struct Store {
    path: PathBuf,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            path: config_base().join("outlook-cli/session.json"),
        }
    }
}

impl Store {
    #[cfg(test)]
    pub const fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> anyhow::Result<SessionFile> {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(data) => Zeroizing::new(data),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SessionFile::default());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", self.path.display()));
            }
        };
        let session: SessionFile = serde_json::from_str(data.as_str())
            .with_context(|| format!("{} is not valid JSON", self.path.display()))?;
        if session.version != CURRENT_VERSION {
            bail!(
                "unsupported session version {} in {} (expected {})",
                session.version,
                self.path.display(),
                CURRENT_VERSION
            );
        }
        warn_if_permissive(&self.path)?;
        Ok(session)
    }

    pub fn acquire_session_lock(&self) -> anyhow::Result<std::fs::File> {
        let path = self.prepare_parent()?.join("session.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        set_mode(&path, 0o600)?;
        fs4::FileExt::try_lock(&file)
            .map_err(|_| anyhow::anyhow!("another outlook operation is already in progress"))?;
        Ok(file)
    }

    pub fn save(&self, session: &SessionFile) -> anyhow::Result<()> {
        let dir = self.prepare_parent()?;
        let mut temporary = tempfile::NamedTempFile::new_in(dir)
            .with_context(|| format!("cannot create a temporary file in {}", dir.display()))?;
        set_mode(temporary.path(), 0o600)?;
        let mut bytes = Zeroizing::new(serde_json::to_vec_pretty(session)?);
        bytes.push(b'\n');
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .map_err(|error| error.error)
            .with_context(|| format!("cannot replace {}", self.path.display()))?;
        set_mode(&self.path, 0o600)?;

        if let Ok(directory) = std::fs::File::open(dir) {
            let _ = directory.sync_all();
        }
        Ok(())
    }

    fn prepare_parent(&self) -> anyhow::Result<&Path> {
        let dir = self
            .path
            .parent()
            .context("session path has no parent directory")?;
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        set_mode(dir, 0o700)?;
        Ok(dir)
    }
}

fn config_base() -> PathBuf {
    if let Some(value) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return value.into();
    }
    std::env::var_os("HOME")
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join(".config")
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("cannot set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn warn_if_permissive(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "warning: {} has mode {mode:03o}; run `chmod 600 {}`",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn warn_if_permissive(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

pub fn now_epoch() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::{MicrosoftSession, SessionFile, Store, StoredCookie, Token};
    use std::collections::BTreeMap;

    #[test]
    fn owner_only_atomic_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/session.json");
        let store = Store::at(path.clone());
        let mut session = SessionFile::default();
        session.config.username = Some("person@example.com".into());
        session.auth.access_token = Some(Token {
            value: "secret".into(),
            expires_at: 42,
            issued_at: Some(1),
        });
        store.save(&session).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.config.username.as_deref(),
            Some("person@example.com")
        );
        assert_eq!(
            loaded
                .auth
                .access_token
                .as_ref()
                .map(|token| token.value.as_str()),
            Some("secret")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn session_operation_lock_is_exclusive() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("nested/session.json"));
        let first = store.acquire_session_lock().unwrap();
        assert!(store.acquire_session_lock().is_err());
        drop(first);
        assert!(store.acquire_session_lock().is_ok());
    }

    #[test]
    fn token_and_session_expiry_obey_skew() {
        let token = Token {
            value: "x".into(),
            expires_at: 200,
            issued_at: None,
        };
        assert!(token.is_valid_at(100, 60));
        assert!(!token.is_valid_at(150, 60));

        let session = MicrosoftSession {
            cookies: BTreeMap::from([(
                "ESTSAUTHPERSISTENT".into(),
                StoredCookie {
                    value: "x".into(),
                    domain: ".login.microsoftonline.com".into(),
                    path: "/".into(),
                    expires_at: 200,
                },
            )]),
            expires_at: 200,
        };
        assert!(session.is_valid_at(199));
        assert!(!session.is_valid_at(200));
    }
}

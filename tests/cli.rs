use std::path::{Path, PathBuf};
use std::process::Command;

fn invoke(home: &Path, args: &[&str], expected_success: bool) -> (String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_outlook"))
        .env("XDG_CONFIG_HOME", home)
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.success(),
        expected_success,
        "outlook {args:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
    (stdout, stderr)
}

fn success(home: &Path, args: &[&str]) -> String {
    invoke(home, args, true).0
}

fn failure(home: &Path, args: &[&str]) -> String {
    invoke(home, args, false).1
}

fn set(home: &Path, key: &str, value: &str) {
    success(home, &["config", "set", key, value]);
}

fn inject_access_token(home: &Path, value: &str) -> PathBuf {
    let path = home.join("outlook-cli/session.json");
    let mut session: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    session["auth"]["access_token"] = serde_json::json!({
        "value": value,
        "expires_at": 4_102_444_800_i64
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&session).unwrap()).unwrap();
    path
}

#[test]
fn help_exposes_requested_command_tree() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let help = success(home, &["--help"]);
    for expected in ["auth", "config", "calendar"] {
        assert!(help.contains(expected));
    }

    let help = success(home, &["auth", "login", "--help"]);
    for absent in [
        "--unattended",
        "--headed",
        "--chrome-profile",
        "--force-microsoft-session",
    ] {
        assert!(!help.contains(absent));
    }

    let help = success(home, &["config", "set", "--help"]);
    for expected in ["authenticator-key", "timezone"] {
        assert!(help.contains(expected));
    }
    for absent in ["time-zone", "totp-command"] {
        assert!(!help.contains(absent));
    }

    let help = success(home, &["calendar", "list", "--help"]);
    for expected in ["--week", "last", "current", "next"] {
        assert!(help.contains(expected));
    }
}

#[test]
fn config_roundtrip_redacts_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    set(home, "username", "person@example.com");
    set(home, "password", "very-secret");
    set(home, "authenticator-key", "base32-secret-value");
    set(home, "timezone", "Pacific Standard Time");
    assert_eq!(
        success(home, &["config", "get", "username"]),
        "person@example.com\n"
    );
    let password = success(home, &["config", "get", "password"]);
    assert!(password.contains("<configured"));
    assert!(!password.contains("very-secret"));
    assert_eq!(
        success(home, &["config", "get", "timezone"]),
        "Pacific Standard Time\n"
    );
    let key = success(home, &["config", "get", "authenticator-key"]);
    assert!(key.contains("<configured"));
    assert!(!key.contains("base32-secret-value"));
    let config = success(home, &["config", "get"]);
    assert!(config.contains("<redacted>"));
    assert!(!config.contains("very-secret"));
    assert!(!config.contains("base32-secret-value"));
}

#[test]
fn login_reuses_a_valid_access_token_without_credentials() {
    let temp = tempfile::tempdir().unwrap();
    set(temp.path(), "username", "person@example.com");
    let path = inject_access_token(temp.path(), "cached-access-token");
    let before = std::fs::read(&path).unwrap();
    assert!(success(temp.path(), &["auth", "login"]).contains("Logged in."));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn login_fallback_requires_an_authenticator_key() {
    let temp = tempfile::tempdir().unwrap();
    set(temp.path(), "username", "person@example.com");
    set(temp.path(), "password", "password-secret");
    let stderr = failure(temp.path(), &["auth", "login"]);
    assert!(stderr.contains("authenticator-key is not configured"));
    assert!(!stderr.contains("password-secret"));
}

#[test]
fn mutating_commands_respect_the_session_lock() {
    let temp = tempfile::tempdir().unwrap();
    set(temp.path(), "username", "first@example.com");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temp.path().join("outlook-cli/session.lock"))
        .unwrap();
    fs4::FileExt::try_lock(&lock).unwrap();
    assert!(
        failure(
            temp.path(),
            &["config", "set", "username", "second@example.com"]
        )
        .contains("another outlook operation")
    );
    fs4::FileExt::unlock(&lock).unwrap();
}

#[test]
fn changing_username_clears_account_bound_authentication() {
    let temp = tempfile::tempdir().unwrap();
    set(temp.path(), "username", "first@example.com");
    let path = inject_access_token(temp.path(), "account-bound-secret");
    set(temp.path(), "username", "second@example.com");
    let updated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(updated["auth"].get("access_token").is_none());
}

#[test]
fn logout_preserves_configuration() {
    let temp = tempfile::tempdir().unwrap();
    set(temp.path(), "username", "person@example.com");
    assert!(success(temp.path(), &["auth", "logout"]).contains("Configuration was preserved"));
    assert_eq!(
        success(temp.path(), &["config", "get", "username"]),
        "person@example.com\n"
    );
}

#[test]
fn status_without_tokens_is_not_logged_in() {
    let temp = tempfile::tempdir().unwrap();
    assert!(success(temp.path(), &["auth", "status"]).contains("not logged in"));
}

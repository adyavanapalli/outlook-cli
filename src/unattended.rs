//! Unattended Microsoft Entra login through an isolated Chrome/CDP session.

use crate::oauth;
use crate::session::{AuthState, Config, MicrosoftSession, StoredCookie, now_epoch};
use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use totp_rs::{Algorithm, Secret, TOTP};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::Message;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{WebSocket, connect};
use url::Url;
use wait_timeout::ChildExt;
use zeroize::Zeroizing;

const CHROME_START_TIMEOUT: Duration = Duration::from_secs(15);
const CDP_CALL_TIMEOUT: Duration = Duration::from_secs(10);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(180);
const STAGE_TIMEOUT: Duration = Duration::from_secs(20);
const AUTH_COOKIE_NAMES: [&str; 2] = ["ESTSAUTHPERSISTENT", "ESTSAUTHPERSISTENT1"];
const LOGIN_HOST: &str = "login.microsoftonline.com";
const OUTLOOK_HOST: &str = "outlook.cloud.microsoft";

const CAPTURE_REDIRECT_SCRIPT: &str = r"
(() => {
  if (location.protocol === 'https:' &&
      location.hostname === 'outlook.cloud.microsoft' &&
      location.pathname === '/mail/' && location.hash) {
    window.name = 'outlook-cli-redirect:' + location.href;
    window.stop();
    location.replace('about:blank');
  }
})();
";

const SNAPSHOT_SCRIPT: &str = r#"
(() => {
  const visible = (element) => {
    if (!element || element.disabled || element.getClientRects().length === 0) return false;
    const style = getComputedStyle(element);
    return style.visibility !== 'hidden' && style.display !== 'none';
  };
  const first = (selectors) => selectors.map((selector) => document.querySelector(selector)).find(visible);
  const controls = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="submit"]')).filter(visible);
  const normalized = (value) => (value || '').replace(/\s+/g, ' ').trim().toLowerCase();
  const controlText = (element) => normalized(element.innerText || element.value || element.getAttribute('aria-label'));
  const hasControl = (texts) => controls.some((element) => texts.includes(controlText(element)));
  const body = normalized(document.body && document.body.innerText).slice(0, 6000);
  const alerts = Array.from(document.querySelectorAll(
    '[role="alert"], #usernameError, #passwordError, #idSpan_SAOTCC_Error_OTC, #errorText, .alert-error'
  )).filter(visible).map((element) => normalized(element.innerText || element.textContent)).filter(Boolean);
  const error = alerts.join(' ').slice(0, 400);
  const aadsts = (body.match(/AADSTS\d+/i) || [])[0] || '';
  const redirect = typeof window.name === 'string' && window.name.startsWith('outlook-cli-redirect:')
    ? window.name.slice('outlook-cli-redirect:'.length)
    : '';

  const otpInput = first(['#idTxtBx_SAOTCC_OTC', 'input[name="otc"]', 'input[autocomplete="one-time-code"]']);
  const otpIsTotp = body.includes('authenticator app') || body.includes('mobile app') ||
    body.includes('time-based') || Boolean(first(['#idA_SAASTO_TOTP', '[data-value="PhoneAppOTP"]']));
  const unsupportedPolicy = body.includes('more information required') ||
    body.includes('help us protect your account') || body.includes('update your password') ||
    body.includes('permissions requested') || Boolean(first(['#idBtn_Accept', '#newPassword', '#confirmNewPassword']));

  let stage = 'unknown';
  if (redirect) {
    stage = 'redirect';
  } else if (location.protocol === 'https:' && location.hostname === 'outlook.cloud.microsoft') {
    stage = 'outlook';
  } else if (unsupportedPolicy) {
    stage = 'unsupported-policy';
  } else if (first(['#i0116', 'input[name="loginfmt"]', 'input[autocomplete="username"]', 'input[type="email"]']) &&
             first(['#i0118', 'input[name="passwd"]', 'input[autocomplete="current-password"]', 'input[type="password"]'])) {
    stage = 'credentials';
  } else if (first(['#i0116', 'input[name="loginfmt"]', 'input[autocomplete="username"]', 'input[type="email"]'])) {
    stage = 'username';
  } else if (first(['#i0118', 'input[name="passwd"]', 'input[autocomplete="current-password"]', 'input[type="password"]'])) {
    stage = 'password';
  } else if (first(['#KmsiDescription', '#KmsiCheckboxField']) || body.includes('stay signed in')) {
    stage = 'kmsi';
  } else if (first(['#idA_SAASTO_TOTP', '[data-value="PhoneAppOTP"]']) ||
             hasControl(['use a verification code', 'enter a code from my authenticator app'])) {
    stage = 'totp-choice';
  } else if (first(['#signInAnotherWay']) ||
             hasControl(["i can't use my microsoft authenticator app right now", 'sign in another way', 'other ways to sign in'])) {
    stage = 'mfa-switch';
  } else if (otpInput) {
    stage = 'otp';
  } else if (first(['#otherTile', '#otherTileText', '[data-test-id="otherTile"]']) || hasControl(['use another account'])) {
    stage = 'account-picker';
  } else if (body.includes('approve sign in request') || body.includes('enter the number shown') ||
             body.includes('security key') || body.includes('use your passkey') || body.includes('verify your identity')) {
    stage = 'unsupported-challenge';
  } else if (error || aadsts) {
    stage = 'error';
  }

  return {
    stage,
    url: location.protocol + '//' + location.host + location.pathname,
    title: (document.title || '').slice(0, 120),
    error,
    aadsts,
    redirect,
    otpIsTotp
  };
})();
"#;

const USERNAME_SELECTORS: [&str; 4] = [
    "#i0116",
    "input[name=\"loginfmt\"]",
    "input[autocomplete=\"username\"]",
    "input[type=\"email\"]",
];
const PASSWORD_SELECTORS: [&str; 4] = [
    "#i0118",
    "input[name=\"passwd\"]",
    "input[autocomplete=\"current-password\"]",
    "input[type=\"password\"]",
];
const TOTP_SELECTORS: [&str; 3] = [
    "#idTxtBx_SAOTCC_OTC",
    "input[name=\"otc\"]",
    "input[autocomplete=\"one-time-code\"]",
];
const SUBMIT_SELECTORS: [&str; 4] = [
    "#idSubmit_SAOTCC_Continue",
    "#idSIButton9",
    "button[type=\"submit\"]",
    "input[type=\"submit\"]",
];

pub fn login(config: &Config) -> anyhow::Result<AuthState> {
    let username = required(config.username.as_deref(), "username")?;
    let password = required(config.password.as_deref(), "password")?;
    let authenticator_key = required(config.authenticator_key.as_deref(), "authenticator-key")?;
    let authorization = oauth::begin_interactive(username)?;
    let executable = chrome_executable(config.chrome_binary.as_deref())?;
    let (mut chrome, websocket_url) = ChromeProcess::launch(&executable)?;
    let mut cdp = Cdp::connect(&websocket_url)?;
    let session_id = create_page(&mut cdp)?;

    cdp.call(Some(&session_id), "Page.enable", json!({}))?;
    cdp.call(Some(&session_id), "Runtime.enable", json!({}))?;
    cdp.call(
        Some(&session_id),
        "Page.addScriptToEvaluateOnNewDocument",
        json!({"source": CAPTURE_REDIRECT_SCRIPT}),
    )?;
    cdp.call(
        Some(&session_id),
        "Page.navigate",
        json!({"url": authorization.url().as_str()}),
    )?;

    let redirect = drive_login(&mut cdp, &session_id, authenticator_key, username, password)?;
    let microsoft_session = read_microsoft_session(&mut cdp)?;
    let auth = oauth::complete_interactive(&authorization, &redirect, microsoft_session)?;

    let _ = cdp.call(None, "Browser.close", json!({}));
    chrome.shutdown(Duration::from_secs(5))?;
    Ok(auth)
}

fn required<'a>(value: Option<&'a str>, name: &str) -> anyhow::Result<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} is not configured; run `outlook config set {name}`"))
}

fn create_page(cdp: &mut Cdp) -> anyhow::Result<String> {
    let target = cdp.call(None, "Target.createTarget", json!({"url": "about:blank"}))?;
    let target_id = target
        .get("targetId")
        .and_then(Value::as_str)
        .context("Chrome did not return a target ID")?;
    let attached = cdp.call(
        None,
        "Target.attachToTarget",
        json!({"targetId": target_id, "flatten": true}),
    )?;
    attached
        .get("sessionId")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .context("Chrome did not return a target session ID")
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct Progress {
    account_picker_clicked: bool,
    username_submitted: bool,
    password_submitted: bool,
    mfa_switch_clicked: bool,
    totp_choice_clicked: bool,
    totp_submitted: bool,
    kmsi_accepted: bool,
    outlook_seen_at: Option<Instant>,
    last_action_at: Option<Instant>,
    unknown_since: Option<Instant>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    stage: String,
    url: String,
    title: String,
    error: String,
    aadsts: String,
    redirect: String,
    otp_is_totp: bool,
}

#[allow(clippy::too_many_lines)]
fn drive_login(
    cdp: &mut Cdp,
    session_id: &str,
    authenticator_key: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<String> {
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    let mut progress = Progress::default();
    loop {
        if Instant::now() >= deadline {
            bail!("unattended Microsoft login timed out after 180 seconds");
        }
        if let Some(redirect) = cdp.take_redirect() {
            let _ = cdp.call(Some(session_id), "Page.stopLoading", json!({}));
            let _ = cdp.call(
                Some(session_id),
                "Page.navigate",
                json!({"url": "about:blank"}),
            );
            return Ok(redirect);
        }
        let snapshot = match cdp.evaluate_value(session_id, SNAPSHOT_SCRIPT) {
            Ok(value) => serde_json::from_value::<Snapshot>(value)
                .context("Chrome returned a malformed login-page snapshot")?,
            Err(error) if transient_context_error(&error) => {
                thread::sleep(Duration::from_millis(250));
                continue;
            }
            Err(error) => return Err(error).context("cannot inspect the Microsoft login page"),
        };
        if !snapshot.redirect.is_empty() {
            return Ok(snapshot.redirect);
        }

        match snapshot.stage.as_str() {
            "account-picker" => {
                ensure_login_origin(&snapshot.url)?;
                if progress.account_picker_clicked {
                    stall_if_needed(&progress, "account picker")?;
                } else {
                    click_control(
                        cdp,
                        session_id,
                        &[
                            "#otherTile",
                            "#otherTileText",
                            "[data-test-id=\"otherTile\"]",
                        ],
                        &["use another account"],
                    )?;
                    progress.account_picker_clicked = true;
                    progress.last_action_at = Some(Instant::now());
                }
            }
            "credentials" => {
                ensure_login_origin(&snapshot.url)?;
                if progress.password_submitted {
                    reject_or_stall(&snapshot, &progress, "credentials")?;
                } else {
                    if !progress.username_submitted {
                        fill_control(cdp, session_id, &USERNAME_SELECTORS, username)?;
                    }
                    fill_control(cdp, session_id, &PASSWORD_SELECTORS, password)?;
                    click_control(cdp, session_id, &SUBMIT_SELECTORS, &["sign in", "next"])?;
                    progress.username_submitted = true;
                    progress.password_submitted = true;
                    progress.last_action_at = Some(Instant::now());
                }
            }
            "username" => {
                ensure_login_origin(&snapshot.url)?;
                if progress.username_submitted {
                    reject_or_stall(&snapshot, &progress, "username")?;
                } else {
                    fill_control(cdp, session_id, &USERNAME_SELECTORS, username)?;
                    click_control(cdp, session_id, &SUBMIT_SELECTORS, &["next"])?;
                    progress.username_submitted = true;
                    progress.last_action_at = Some(Instant::now());
                }
            }
            "password" => {
                ensure_login_origin(&snapshot.url)?;
                if progress.password_submitted {
                    reject_or_stall(&snapshot, &progress, "password")?;
                } else {
                    fill_control(cdp, session_id, &PASSWORD_SELECTORS, password)?;
                    click_control(cdp, session_id, &SUBMIT_SELECTORS, &["sign in"])?;
                    progress.password_submitted = true;
                    progress.last_action_at = Some(Instant::now());
                }
            }
            "mfa-switch" => {
                ensure_login_origin(&snapshot.url)?;
                if progress.mfa_switch_clicked {
                    stall_if_needed(&progress, "MFA method chooser")?;
                } else {
                    click_control(
                        cdp,
                        session_id,
                        &["#signInAnotherWay"],
                        &[
                            "i can't use my microsoft authenticator app right now",
                            "sign in another way",
                            "other ways to sign in",
                        ],
                    )?;
                    progress.mfa_switch_clicked = true;
                    progress.last_action_at = Some(Instant::now());
                }
            }
            "totp-choice" => {
                ensure_login_origin(&snapshot.url)?;
                if progress.totp_choice_clicked {
                    stall_if_needed(&progress, "TOTP method selection")?;
                } else {
                    click_control(
                        cdp,
                        session_id,
                        &["#idA_SAASTO_TOTP", "[data-value=\"PhoneAppOTP\"]"],
                        &[
                            "use a verification code",
                            "enter a code from my authenticator app",
                        ],
                    )?;
                    progress.totp_choice_clicked = true;
                    progress.last_action_at = Some(Instant::now());
                }
            }
            "otp" => {
                ensure_login_origin(&snapshot.url)?;
                if !snapshot.otp_is_totp && !progress.totp_choice_clicked {
                    bail!(
                        "Microsoft requested a non-Authenticator one-time code; refusing to submit the configured TOTP"
                    );
                }
                if progress.totp_submitted {
                    reject_or_stall(&snapshot, &progress, "verification code")?;
                } else {
                    let code = current_authenticator_code(authenticator_key)?;
                    let _ = check_control(
                        cdp,
                        session_id,
                        &["#idChkBx_SAOTCC_TD", "input[name=\"DontShowAgain\"]"],
                    );
                    fill_control(cdp, session_id, &TOTP_SELECTORS, &code)?;
                    click_control(cdp, session_id, &SUBMIT_SELECTORS, &["verify", "next"])?;
                    progress.totp_submitted = true;
                    progress.last_action_at = Some(Instant::now());
                }
            }
            "kmsi" => {
                ensure_login_origin(&snapshot.url)?;
                if progress.kmsi_accepted {
                    stall_if_needed(&progress, "stay-signed-in confirmation")?;
                } else {
                    let _ = check_control(
                        cdp,
                        session_id,
                        &["#KmsiCheckboxField", "input[name=\"KmsiCheckboxField\"]"],
                    );
                    click_control(cdp, session_id, &["#idSIButton9"], &["yes"])?;
                    progress.kmsi_accepted = true;
                    progress.last_action_at = Some(Instant::now());
                }
            }
            "redirect" => return Ok(snapshot.redirect),
            "outlook" => {
                progress.outlook_seen_at.get_or_insert_with(Instant::now);
                if progress
                    .outlook_seen_at
                    .is_some_and(|seen| seen.elapsed() > Duration::from_secs(10))
                {
                    bail!("Outlook loaded, but the OAuth authorization redirect was not captured");
                }
            }
            "unsupported-challenge" => bail!(
                "Microsoft requires an unsupported MFA challenge; TOTP authenticator verification must be available"
            ),
            "unsupported-policy" => bail!(
                "Microsoft requires an interactive policy, consent, password-change, or security-registration step"
            ),
            "error" => return Err(login_rejection(&snapshot, "sign-in")),
            _ => {
                if !snapshot.error.is_empty() || !snapshot.aadsts.is_empty() {
                    return Err(login_rejection(&snapshot, "sign-in"));
                }
                let unknown_since = progress.unknown_since.get_or_insert_with(Instant::now);
                if unknown_since.elapsed() > STAGE_TIMEOUT {
                    let title = sanitized_title(&snapshot.title);
                    bail!("unsupported Microsoft login page{title}");
                }
            }
        }
        if snapshot.stage != "unknown" {
            progress.unknown_since = None;
        }
        thread::sleep(Duration::from_millis(300));
    }
}

fn reject_or_stall(
    snapshot: &Snapshot,
    progress: &Progress,
    credential: &str,
) -> anyhow::Result<()> {
    if !snapshot.error.is_empty() || !snapshot.aadsts.is_empty() {
        return Err(login_rejection(snapshot, credential));
    }
    stall_if_needed(progress, credential)
}

fn stall_if_needed(progress: &Progress, stage: &str) -> anyhow::Result<()> {
    if progress
        .last_action_at
        .is_some_and(|action| action.elapsed() > STAGE_TIMEOUT)
    {
        bail!("Microsoft login did not advance after the {stage} step");
    }
    Ok(())
}

fn login_rejection(snapshot: &Snapshot, credential: &str) -> anyhow::Error {
    let aadsts = if snapshot.aadsts.is_empty() {
        String::new()
    } else {
        format!(" ({})", snapshot.aadsts)
    };
    let detail = sanitized_page_error(&snapshot.error);
    if detail.is_empty() {
        anyhow::anyhow!("Microsoft rejected the {credential}{aadsts}")
    } else {
        anyhow::anyhow!("Microsoft rejected the {credential}{aadsts}: {detail}")
    }
}

fn sanitized_page_error(error: &str) -> String {
    error
        .split_ascii_whitespace()
        .map(|word| {
            if word.contains('@') {
                "<redacted-account>"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|character| !character.is_control())
        .take(300)
        .collect()
}

fn sanitized_title(title: &str) -> String {
    let title = title.trim();
    if title.is_empty() {
        String::new()
    } else {
        format!(" titled {:?}", title.chars().take(80).collect::<String>())
    }
}

fn transient_context_error(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}");
    message.contains("Execution context was destroyed")
        || message.contains("Cannot find context")
        || message.contains("Inspected target navigated or closed")
}

fn ensure_login_origin(page_url: &str) -> anyhow::Result<()> {
    let url = Url::parse(page_url).context("Microsoft login page URL was malformed")?;
    if url.scheme() != "https" || url.host_str() != Some(LOGIN_HOST) {
        bail!("refusing to send credentials to an unexpected login origin");
    }
    Ok(())
}

fn fill_control(
    cdp: &mut Cdp,
    session_id: &str,
    selectors: &[&str],
    secret: &str,
) -> anyhow::Result<()> {
    let selector_json = serde_json::to_string(selectors)?;
    let expression = format!(
        "(() => {{ const visible = e => e && !e.disabled && e.getClientRects().length > 0; return {selector_json}.map(s => document.querySelector(s)).find(visible) || null; }})()"
    );
    let evaluated = cdp.call(
        Some(session_id),
        "Runtime.evaluate",
        json!({
            "expression": expression,
            "returnByValue": false,
            "awaitPromise": false,
            "userGesture": true
        }),
    )?;
    let object_id = evaluated
        .get("result")
        .and_then(|result| result.get("objectId"))
        .and_then(Value::as_str)
        .context("Microsoft login input was not found")?
        .to_string();
    let result = cdp.call(
        Some(session_id),
        "Runtime.callFunctionOn",
        json!({
            "objectId": object_id,
            "functionDeclaration": "function(value) { const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set; setter.call(this, value); this.dispatchEvent(new Event('input', {bubbles: true})); this.dispatchEvent(new Event('change', {bubbles: true})); this.focus(); return true; }",
            "arguments": [{"value": secret}],
            "returnByValue": true,
            "awaitPromise": false,
            "userGesture": true
        }),
    );
    let _ = cdp.call(
        Some(session_id),
        "Runtime.releaseObject",
        json!({"objectId": object_id}),
    );
    let response = result.context("cannot fill a Microsoft login input")?;
    if response.get("exceptionDetails").is_some()
        || response.pointer("/result/value").and_then(Value::as_bool) != Some(true)
    {
        bail!("Microsoft login input rejected the supplied value");
    }
    Ok(())
}

fn click_control(
    cdp: &mut Cdp,
    session_id: &str,
    selectors: &[&str],
    exact_texts: &[&str],
) -> anyhow::Result<()> {
    let selector_json = serde_json::to_string(selectors)?;
    let text_json = serde_json::to_string(exact_texts)?;
    let expression = format!(
        r#"(() => {{
          const visible = e => e && !e.disabled && e.getClientRects().length > 0;
          const normalized = value => (value || '').replace(/\s+/g, ' ').trim().toLowerCase();
          let element = {selector_json}.map(s => document.querySelector(s)).find(visible);
          if (!element) {{
            const texts = {text_json};
            element = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="submit"]'))
              .filter(visible)
              .find(e => texts.includes(normalized(e.innerText || e.value || e.getAttribute('aria-label'))));
          }}
          if (!element) return false;
          element.click();
          return true;
        }})()"#
    );
    let clicked = cdp.evaluate_value(session_id, &expression)?;
    if clicked.as_bool() != Some(true) {
        bail!("the expected Microsoft login control was not found");
    }
    Ok(())
}

fn check_control(cdp: &mut Cdp, session_id: &str, selectors: &[&str]) -> anyhow::Result<bool> {
    let selector_json = serde_json::to_string(selectors)?;
    let expression = format!(
        r#"(() => {{
          const visible = e => e && !e.disabled && e.getClientRects().length > 0;
          let element = {selector_json}.map(s => document.querySelector(s)).find(visible);
          if (element && element.tagName !== 'INPUT') element = element.querySelector('input[type="checkbox"]');
          if (!visible(element) || element.type !== 'checkbox') return false;
          if (!element.checked) element.click();
          return element.checked;
        }})()"#
    );
    Ok(cdp.evaluate_value(session_id, &expression)?.as_bool() == Some(true))
}

fn current_authenticator_code(key: &str) -> anyhow::Result<Zeroizing<String>> {
    let totp = if key.trim_start().starts_with("otpauth://") {
        TOTP::from_url(key.trim()).context("configured authenticator-key URI is invalid")?
    } else {
        let normalized = Zeroizing::new(
            key.chars()
                .filter(|character| {
                    !character.is_ascii_whitespace() && *character != '-' && *character != '='
                })
                .flat_map(char::to_uppercase)
                .collect::<String>(),
        );
        let bytes = Secret::Encoded(normalized.to_string())
            .to_bytes()
            .context("configured authenticator-key is not valid base32")?;
        // Microsoft can issue 80-bit manual setup keys. The checked constructor
        // enforces the RFC recommendation of 128 bits and rejects those valid
        // provider-issued keys, so validate Microsoft's minimum below instead.
        TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, bytes, None, String::new())
    };
    if totp.secret.len() < 10 {
        bail!("configured authenticator-key must contain at least 80 bits");
    }
    totp.generate_current()
        .map(Zeroizing::new)
        .context("cannot generate the current TOTP code")
}

#[derive(Deserialize)]
struct CookieResult {
    cookies: Vec<BrowserCookie>,
}

#[derive(Deserialize)]
struct BrowserCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    expires: f64,
}

fn read_microsoft_session(cdp: &mut Cdp) -> anyhow::Result<Option<MicrosoftSession>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let result = cdp.call(None, "Storage.getCookies", json!({}))?;
        let response: CookieResult =
            serde_json::from_value(result).context("Chrome returned malformed cookie metadata")?;
        let mut cookies = BTreeMap::new();
        for cookie in response.cookies {
            let Some(expires_at) = cookie_expiry(cookie.expires) else {
                continue;
            };
            if AUTH_COOKIE_NAMES.contains(&cookie.name.as_str())
                && microsoft_cookie_domain(&cookie.domain)
                && !cookie.value.is_empty()
                && expires_at > now_epoch()
            {
                cookies.insert(
                    cookie.name,
                    StoredCookie {
                        value: cookie.value,
                        domain: cookie.domain,
                        path: cookie.path,
                        expires_at,
                    },
                );
            }
        }
        if let Some(expires_at) = cookies.values().map(|cookie| cookie.expires_at).min() {
            return Ok(Some(MicrosoftSession {
                cookies,
                expires_at,
            }));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[allow(clippy::cast_possible_truncation)]
fn cookie_expiry(value: f64) -> Option<i64> {
    if value.is_finite() && (1.0..=10_000_000_000.0).contains(&value) {
        Some(value.floor() as i64)
    } else {
        None
    }
}

fn microsoft_cookie_domain(domain: &str) -> bool {
    domain
        .trim_start_matches('.')
        .eq_ignore_ascii_case(LOGIN_HOST)
}

struct ChromeProcess {
    child: Option<Child>,
    profile: TempDir,
}

impl ChromeProcess {
    fn launch(executable: &Path) -> anyhow::Result<(Self, String)> {
        let profile = tempfile::Builder::new()
            .prefix("outlook-cli-login-")
            .tempdir()
            .context("cannot create an isolated Chrome profile")?;
        set_owner_only(profile.path())?;
        let chrome_tmp = profile.path().join("tmp");
        std::fs::create_dir(&chrome_tmp)?;
        set_owner_only(&chrome_tmp)?;
        let profile_argument = format!("--user-data-dir={}", profile.path().display());
        let arguments: Vec<OsString> = vec![
            "--remote-debugging-port=0".into(),
            "--remote-debugging-address=127.0.0.1".into(),
            profile_argument.into(),
            "--profile-directory=Default".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-sync".into(),
            "--disable-extensions".into(),
            "--disable-component-extensions-with-background-pages".into(),
            "--disable-default-apps".into(),
            "--disable-breakpad".into(),
            "--disable-crash-reporter".into(),
            "--disable-dev-shm-usage".into(),
            "--disable-popup-blocking".into(),
            "--disable-features=TranslateUI".into(),
            "--lang=en-US".into(),
            "--window-size=1280,900".into(),
            "--password-store=basic".into(),
            "--use-mock-keychain".into(),
            "--headless=new".into(),
            "--disable-gpu".into(),
            "about:blank".into(),
        ];
        let child = Command::new(executable)
            .args(&arguments)
            .env("TMPDIR", &chrome_tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("cannot launch Chrome at {}", executable.display()))?;
        let mut process = Self {
            child: Some(child),
            profile,
        };
        let websocket_url = process.wait_for_debugger()?;
        Ok((process, websocket_url))
    }

    fn wait_for_debugger(&mut self) -> anyhow::Result<String> {
        let active_port = self.profile.path().join("DevToolsActivePort");
        let deadline = Instant::now() + CHROME_START_TIMEOUT;
        loop {
            if let Ok(contents) = std::fs::read_to_string(&active_port)
                && let Ok(url) = parse_active_port(&contents)
            {
                return Ok(url);
            }
            if let Some(status) = self
                .child
                .as_mut()
                .context("Chrome process is unavailable")?
                .try_wait()?
            {
                bail!("Chrome exited before remote debugging started ({status})");
            }
            if Instant::now() >= deadline {
                bail!("Chrome did not start remote debugging within 15 seconds");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn shutdown(&mut self, timeout: Duration) -> anyhow::Result<()> {
        if let Some(child) = self.child.as_mut()
            && !matches!(child.wait_timeout(timeout), Ok(Some(_)))
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        self.remove_profile()
    }

    fn remove_profile(&self) -> anyhow::Result<()> {
        let path = self.profile.path();
        for _ in 0..20 {
            let removed = match std::fs::remove_dir_all(path) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            thread::sleep(Duration::from_millis(100));
            if removed && !path.exists() {
                return Ok(());
            }
        }
        std::fs::remove_dir_all(path)
            .with_context(|| format!("cannot delete temporary Chrome profile {}", path.display()))
    }
}

impl Drop for ChromeProcess {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown(Duration::from_secs(1)) {
            eprintln!("warning: {error:#}");
        }
    }
}

fn parse_active_port(contents: &str) -> anyhow::Result<String> {
    if contents.len() > 1024 {
        bail!("Chrome DevToolsActivePort file is unexpectedly large");
    }
    let mut lines = contents.lines();
    let port = lines
        .next()
        .context("Chrome DevToolsActivePort has no port")?
        .parse::<u16>()
        .context("Chrome DevToolsActivePort has an invalid port")?;
    if port == 0 {
        bail!("Chrome DevToolsActivePort contains port zero");
    }
    let path = lines
        .next()
        .context("Chrome DevToolsActivePort has no WebSocket path")?;
    if !path.starts_with("/devtools/browser/")
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
    {
        bail!("Chrome DevToolsActivePort has an invalid WebSocket path");
    }
    Ok(format!("ws://127.0.0.1:{port}{path}"))
}

fn chrome_executable(configured: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(path) = configured {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        bail!("configured chrome-binary {} does not exist", path.display());
    }
    for name in [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ] {
        if let Some(path) = executable_on_path(name) {
            return Ok(path);
        }
    }
    bail!(
        "Chrome was not found; configure it with `outlook config set chrome-binary /path/to/google-chrome`"
    )
}

fn executable_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

struct Cdp {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    redirect: Option<String>,
}

impl Cdp {
    fn connect(websocket_url: &str) -> anyhow::Result<Self> {
        let mut request = websocket_url
            .into_client_request()
            .context("cannot build Chrome WebSocket request")?;
        request.headers_mut().remove("origin");
        let (mut socket, _) = connect(request).context("cannot connect to Chrome DevTools")?;
        match socket.get_mut() {
            MaybeTlsStream::Plain(stream) => {
                stream.set_read_timeout(Some(CDP_CALL_TIMEOUT))?;
                stream.set_write_timeout(Some(CDP_CALL_TIMEOUT))?;
                stream.set_nodelay(true)?;
            }
            _ => bail!("Chrome DevTools unexpectedly used a TLS connection"),
        }
        Ok(Self {
            socket,
            next_id: 0,
            redirect: None,
        })
    }

    fn call(
        &mut self,
        session_id: Option<&str>,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let mut request = json!({"id": id, "method": method});
        request["params"] = params;
        if let Some(session_id) = session_id {
            request["sessionId"] = Value::String(session_id.to_string());
        }
        let payload = serde_json::to_string(&request)?;
        self.socket
            .send(Message::text(payload))
            .with_context(|| format!("cannot send Chrome DevTools command {method}"))?;
        let deadline = Instant::now() + CDP_CALL_TIMEOUT;
        loop {
            if Instant::now() >= deadline {
                bail!("Chrome DevTools command {method} timed out");
            }
            let message = self
                .socket
                .read()
                .with_context(|| format!("cannot read Chrome DevTools response for {method}"))?;
            match message {
                Message::Text(text) => {
                    let message: Value = serde_json::from_str(text.as_str())
                        .context("Chrome DevTools returned malformed JSON")?;
                    if message.get("id").and_then(Value::as_u64) == Some(id) {
                        if let Some(error) = message.get("error") {
                            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
                            let detail = error
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown protocol error")
                                .chars()
                                .take(200)
                                .collect::<String>();
                            bail!("Chrome DevTools {method} failed ({code}): {detail}");
                        }
                        return message
                            .get("result")
                            .cloned()
                            .context("Chrome DevTools response had no result");
                    }
                    self.observe_event(&message);
                }
                Message::Ping(payload) => {
                    self.socket.send(Message::Pong(payload))?;
                }
                Message::Close(_) => bail!("Chrome closed the DevTools connection"),
                Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    fn evaluate_value(&mut self, session_id: &str, expression: &str) -> anyhow::Result<Value> {
        let response = self.call(
            Some(session_id),
            "Runtime.evaluate",
            json!({
                "expression": expression,
                "returnByValue": true,
                "awaitPromise": true,
                "userGesture": true
            }),
        )?;
        if let Some(exception) = response.get("exceptionDetails") {
            let detail = exception
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("JavaScript evaluation failed")
                .chars()
                .take(200)
                .collect::<String>();
            bail!("Chrome JavaScript evaluation failed: {detail}");
        }
        response
            .get("result")
            .and_then(|result| result.get("value"))
            .cloned()
            .context("Chrome JavaScript evaluation returned no value")
    }

    fn observe_event(&mut self, message: &Value) {
        let method = message.get("method").and_then(Value::as_str);
        let url = match method {
            Some("Page.frameNavigated") => {
                message.pointer("/params/frame/url").and_then(Value::as_str)
            }
            Some("Page.navigatedWithinDocument") => {
                message.pointer("/params/url").and_then(Value::as_str)
            }
            _ => None,
        };
        if let Some(url) = url
            && is_authorization_redirect(url)
        {
            self.redirect = Some(url.to_string());
        }
    }

    const fn take_redirect(&mut self) -> Option<String> {
        self.redirect.take()
    }
}

fn is_authorization_redirect(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some(OUTLOOK_HOST)
            && url.path() == "/mail/"
            && url
                .fragment()
                .is_some_and(|fragment| fragment.contains("code=") || fragment.contains("error="))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Cdp, ChromeProcess, chrome_executable, create_page, current_authenticator_code,
        is_authorization_redirect, microsoft_cookie_domain, parse_active_port,
        sanitized_page_error,
    };
    use serde_json::json;

    #[test]
    fn parses_bounded_loopback_devtools_endpoint() {
        let url = parse_active_port("9222\n/devtools/browser/abc-123\n").unwrap();
        assert_eq!(url, "ws://127.0.0.1:9222/devtools/browser/abc-123");
        assert!(parse_active_port("0\n/devtools/browser/abc\n").is_err());
        assert!(parse_active_port("9222\nhttp://evil.example/x\n").is_err());
    }

    #[test]
    fn recognizes_only_expected_redirects_and_cookie_domain() {
        assert!(is_authorization_redirect(
            "https://outlook.cloud.microsoft/mail/#code=x&state=y"
        ));
        assert!(!is_authorization_redirect(
            "https://evil.example/mail/#code=x&state=y"
        ));
        assert!(microsoft_cookie_domain(".login.microsoftonline.com"));
        assert!(!microsoft_cookie_domain(
            "login.microsoftonline.com.evil.example"
        ));
    }

    #[test]
    fn generates_six_digit_totp_from_authenticator_key() {
        let code = current_authenticator_code("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn rejects_authenticator_keys_shorter_than_eighty_bits() {
        assert!(current_authenticator_code("JBSWY3DP").is_err());
    }

    #[test]
    fn login_page_errors_redact_account_identifiers() {
        assert_eq!(
            sanitized_page_error("account person@example.com was not found"),
            "account <redacted-account> was not found"
        );
    }

    #[test]
    fn finds_configured_chrome_binary() {
        let path = std::path::Path::new("/usr/bin/google-chrome");
        if path.exists() {
            assert_eq!(chrome_executable(Some(path)).unwrap(), path);
        }
    }

    #[test]
    #[ignore = "requires a locally installed Chrome browser"]
    fn real_chrome_cdp_smoke() {
        let executable = chrome_executable(None).unwrap();
        let (mut chrome, websocket) = ChromeProcess::launch(&executable).unwrap();
        let mut cdp = Cdp::connect(&websocket).unwrap();
        let session_id = create_page(&mut cdp).unwrap();
        cdp.call(Some(&session_id), "Runtime.enable", json!({}))
            .unwrap();
        cdp.call(None, "Storage.getCookies", json!({})).unwrap();
        let _ = cdp.call(None, "Browser.close", json!({}));
        chrome.shutdown(std::time::Duration::from_secs(5)).unwrap();
    }
}

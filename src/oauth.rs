//! Microsoft identity token parsing and silent renewal for Outlook Web.

use crate::session::{AuthState, MicrosoftSession, Token, now_epoch};
use anyhow::{Context, bail};
use base64::Engine;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::cookie::{CookieStore, Jar};
use reqwest::header::{LOCATION, ORIGIN, REFERER};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const CLIENT_ID: &str = "9199bf20-a13f-4107-85dc-02114787ef48";
pub const REDIRECT_URI: &str = "https://outlook.cloud.microsoft/mail/";
pub const SCOPE: &str = "https://outlook.office.com/.default openid profile offline_access";
const AUTHORIZE_ENDPOINT: &str =
    "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
const TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
const LOGIN_ORIGIN: &str = "https://login.microsoftonline.com/";
const OUTLOOK_ORIGIN: &str = "https://outlook.cloud.microsoft";
const MSAL_VERSION: &str = "5.12.0";
const ACCESS_SKEW_SECONDS: i64 = 120;

#[derive(Clone, Debug, Deserialize)]
pub struct JwtClaims {
    pub exp: i64,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub tid: Option<String>,
    #[serde(default)]
    pub puid: Option<String>,
    #[serde(default)]
    pub upn: Option<String>,
    #[serde(default)]
    pub unique_name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
}

impl JwtClaims {
    pub fn matches_username(&self, expected: &str) -> bool {
        [
            self.preferred_username.as_deref(),
            self.upn.as_deref(),
            self.unique_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|actual| actual.eq_ignore_ascii_case(expected))
    }
}

pub fn decode_jwt_claims(token: &str) -> anyhow::Result<JwtClaims> {
    let payload = token
        .split('.')
        .nth(1)
        .context("token does not have a JWT payload")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("JWT payload is not valid base64url")?;
    serde_json::from_slice(&bytes).context("JWT payload is not valid JSON")
}

pub fn access_token_matches_username(token: &str, expected: &str) -> anyhow::Result<bool> {
    Ok(decode_jwt_claims(token)?.matches_username(expected))
}

pub fn access_is_valid(auth: &AuthState) -> bool {
    auth.access_token
        .as_ref()
        .is_some_and(|token| token.is_valid_at(now_epoch(), ACCESS_SKEW_SECONDS))
}

pub fn refresh_access_token(
    auth: &mut AuthState,
    configured_username: Option<&str>,
) -> anyhow::Result<()> {
    let now = now_epoch();
    let refresh = auth
        .refresh_token
        .as_ref()
        .filter(|token| token.is_valid_at(now, 0))
        .context("refresh token is absent or expired")?;
    let response = token_client()?
        .post(TOKEN_ENDPOINT)
        .header(ORIGIN, OUTLOOK_ORIGIN)
        .header(REFERER, format!("{OUTLOOK_ORIGIN}/"))
        .header("x-client-sku", "msal.js.browser")
        .header("x-client-ver", MSAL_VERSION)
        .header("client-request-id", Uuid::new_v4().to_string())
        .form(&[
            ("client_id", CLIENT_ID),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.value.as_str()),
            ("scope", SCOPE),
            ("client_info", "1"),
        ])
        .send()
        .context("Microsoft refresh-token request failed")?;
    let inherited_expiry = refresh.expires_at;
    let tokens = parse_token_response(response)?;
    validate_token_response_identity(auth, &tokens, configured_username)?;
    apply_tokens(auth, tokens, Some(inherited_expiry))
}

pub fn renew_from_microsoft_session(
    auth: &mut AuthState,
    configured_username: Option<&str>,
) -> anyhow::Result<()> {
    let session = auth
        .microsoft_session
        .as_ref()
        .filter(|session| session.is_valid_at(now_epoch()))
        .context("Microsoft persistent session is absent or expired")?;
    let username = configured_username
        .context("configured username is required for silent Microsoft session renewal")?;
    let grant = silent_authorization_code(session, username)?;
    let tokens = exchange_authorization_code(&grant.code, &grant.verifier)?;
    validate_token_response_identity(auth, &tokens, Some(username))?;
    apply_tokens(auth, tokens, None)?;
    update_session_cookies(auth, &grant.jar, &grant.login_url);
    Ok(())
}

struct AuthorizationGrant {
    code: Zeroizing<String>,
    verifier: Zeroizing<String>,
    jar: Arc<Jar>,
    login_url: Url,
}

pub struct InteractiveAuthorization {
    url: Url,
    verifier: Zeroizing<String>,
    state: String,
    expected_username: String,
}

impl InteractiveAuthorization {
    pub const fn url(&self) -> &Url {
        &self.url
    }
}

fn silent_authorization_code(
    session: &MicrosoftSession,
    username: &str,
) -> anyhow::Result<AuthorizationGrant> {
    let jar = Arc::new(Jar::default());
    let login_url = Url::parse(LOGIN_ORIGIN)?;
    for (name, cookie) in &session.cookies {
        if !cookie
            .domain
            .trim_start_matches('.')
            .eq_ignore_ascii_case("login.microsoftonline.com")
        {
            bail!("stored Microsoft session contains an unexpected cookie domain");
        }
        let path = if cookie.path.starts_with('/') {
            cookie.path.as_str()
        } else {
            "/"
        };
        jar.add_cookie_str(
            &format!(
                "{name}={}; Domain={}; Path={path}; Secure; HttpOnly",
                cookie.value, cookie.domain
            ),
            &login_url,
        );
    }
    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 10 {
            attempt.error("too many Microsoft authorization redirects")
        } else if attempt.url().scheme() == "https"
            && attempt.url().host_str() == Some("outlook.cloud.microsoft")
        {
            attempt.stop()
        } else if attempt.url().scheme() == "https"
            && attempt.url().host_str().is_some_and(|host| {
                host == "login.microsoftonline.com" || host.ends_with(".microsoftonline.com")
            })
        {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    let client = ClientBuilder::new()
        .cookie_provider(Arc::clone(&jar))
        .redirect(redirect_policy)
        .timeout(Duration::from_secs(30))
        .user_agent(crate::owa::USER_AGENT)
        .build()?;
    let request = authorization_request(username, "none")?;
    let response = client
        .get(request.url.clone())
        .send()
        .context("silent Microsoft authorization request failed")?;
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .context(
            "Microsoft session did not produce an authorization redirect; interactive login is required",
        )?;
    let redirect = response.url().join(location)?;
    if redirect.host_str() != Some("outlook.cloud.microsoft") {
        bail!(
            "Microsoft session redirected to {} instead of Outlook; interactive login is required",
            redirect.host_str().unwrap_or("an unknown host")
        );
    }
    let code = authorization_code_from_redirect(&redirect, &request.state)?;
    Ok(AuthorizationGrant {
        code,
        verifier: request.verifier,
        jar,
        login_url,
    })
}

pub fn begin_interactive(username: &str) -> anyhow::Result<InteractiveAuthorization> {
    authorization_request(username, "login")
}

pub fn complete_interactive(
    authorization: &InteractiveAuthorization,
    redirect_url: &str,
    microsoft_session: Option<MicrosoftSession>,
) -> anyhow::Result<AuthState> {
    let redirect = Url::parse(redirect_url).context("Microsoft redirect URL was malformed")?;
    let code = authorization_code_from_redirect(&redirect, &authorization.state)?;
    let tokens = exchange_authorization_code(&code, &authorization.verifier)?;
    let mut auth = AuthState::default();
    validate_token_response_identity(&auth, &tokens, Some(&authorization.expected_username))?;
    apply_tokens(&mut auth, tokens, None)?;
    auth.microsoft_session = microsoft_session;
    auth.client_version = Some(crate::owa::DEFAULT_CLIENT_VERSION.to_string());
    Ok(auth)
}

fn authorization_request(username: &str, prompt: &str) -> anyhow::Result<InteractiveAuthorization> {
    let verifier = Zeroizing::new(pkce_verifier());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let state = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let request_id = Uuid::new_v4().to_string();
    let claims = r#"{"access_token":{"xms_cc":{"values":["CP1"]}}}"#;
    let url = Url::parse_with_params(
        AUTHORIZE_ENDPOINT,
        [
            ("client_id", CLIENT_ID),
            ("scope", SCOPE),
            ("redirect_uri", REDIRECT_URI),
            ("client-request-id", request_id.as_str()),
            ("response_mode", "fragment"),
            ("client_info", "1"),
            ("prompt", prompt),
            ("login_hint", username),
            ("nonce", nonce.as_str()),
            ("state", state.as_str()),
            ("claims", claims),
            ("x-client-SKU", "msal.js.browser"),
            ("x-client-VER", MSAL_VERSION),
            ("response_type", "code"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ],
    )?;
    Ok(InteractiveAuthorization {
        url,
        verifier,
        state,
        expected_username: username.to_string(),
    })
}

fn authorization_code_from_redirect(
    redirect: &Url,
    expected_state: &str,
) -> anyhow::Result<Zeroizing<String>> {
    if redirect.scheme() != "https"
        || redirect.host_str() != Some("outlook.cloud.microsoft")
        || redirect.path() != "/mail/"
    {
        bail!("Microsoft authorization did not redirect to the expected Outlook origin");
    }
    let parameters: std::collections::HashMap<String, String> = redirect
        .fragment()
        .map(|fragment| {
            url::form_urlencoded::parse(fragment.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(error) = parameters.get("error") {
        let description: String = parameters
            .get("error_description")
            .map_or("", String::as_str)
            .chars()
            .take(300)
            .collect();
        bail!("Microsoft authorization failed: {error}: {description}");
    }
    if parameters.get("state").map(String::as_str) != Some(expected_state) {
        bail!("Microsoft authorization state mismatch");
    }
    let code = parameters
        .get("code")
        .context("Microsoft authorization redirect did not contain a code")?
        .clone();
    Ok(Zeroizing::new(code))
}

fn exchange_authorization_code(code: &str, verifier: &str) -> anyhow::Result<TokenResponse> {
    let response = token_client()?
        .post(TOKEN_ENDPOINT)
        .header(ORIGIN, OUTLOOK_ORIGIN)
        .header(REFERER, format!("{OUTLOOK_ORIGIN}/"))
        .header("x-client-sku", "msal.js.browser")
        .header("x-client-ver", MSAL_VERSION)
        .header("client-request-id", Uuid::new_v4().to_string())
        .form(&[
            ("client_id", CLIENT_ID),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
            ("scope", SCOPE),
            ("client_info", "1"),
        ])
        .send()
        .context("Microsoft authorization-code exchange failed")?;
    parse_token_response(response)
}

fn update_session_cookies(auth: &mut AuthState, jar: &Jar, login_url: &Url) {
    let Some(cookie_header) = jar
        .cookies(login_url)
        .and_then(|value| value.to_str().ok().map(str::to_owned))
    else {
        return;
    };
    let Some(saved_session) = auth.microsoft_session.as_mut() else {
        return;
    };
    for pair in cookie_header.split(';') {
        if let Some((name, value)) = pair.trim().split_once('=')
            && let Some(cookie) = saved_session.cookies.get_mut(name)
        {
            cookie.value = value.to_string();
        }
    }
}

fn token_client() -> anyhow::Result<Client> {
    ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent(crate::owa::USER_AGENT)
        .build()
        .context("cannot build Microsoft token client")
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: i64,
    #[serde(default)]
    refresh_token_expires_in: Option<i64>,
    #[serde(default)]
    client_info: Option<String>,
}

#[derive(Deserialize)]
struct ClientInfo {
    uid: String,
    utid: String,
}

#[derive(Deserialize)]
struct TokenError {
    error: String,
    #[serde(default)]
    error_description: String,
}

fn parse_token_response(response: reqwest::blocking::Response) -> anyhow::Result<TokenResponse> {
    let status = response.status();
    let bytes = response.bytes()?;
    if status.is_success() {
        return serde_json::from_slice(&bytes).context("Microsoft token response was malformed");
    }
    if let Ok(error) = serde_json::from_slice::<TokenError>(&bytes) {
        bail!(
            "Microsoft token endpoint returned {status}: {}: {}",
            error.error,
            error.error_description
        );
    }
    let snippet: String = String::from_utf8_lossy(&bytes).chars().take(200).collect();
    bail!("Microsoft token endpoint returned {status}: {snippet}")
}

fn validate_token_response_identity(
    auth: &AuthState,
    response: &TokenResponse,
    expected_username: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(expected) = expected_username
        && !access_token_matches_username(&response.access_token, expected)?
    {
        bail!("Microsoft returned a token for a different username");
    }
    if let (Some(expected_home), Some(client_info)) = (
        auth.home_account_id.as_deref(),
        response
            .client_info
            .as_deref()
            .map(decode_client_info)
            .transpose()?,
    ) {
        let actual_home = format!("{}.{}", client_info.uid, client_info.utid);
        if !expected_home.eq_ignore_ascii_case(&actual_home) {
            bail!("Microsoft returned a token for a different account");
        }
    }
    Ok(())
}

fn apply_tokens(
    auth: &mut AuthState,
    response: TokenResponse,
    inherited_refresh_expiry: Option<i64>,
) -> anyhow::Result<()> {
    let now = now_epoch();
    let claims = decode_jwt_claims(&response.access_token)?;
    let client_info = response
        .client_info
        .as_deref()
        .map(decode_client_info)
        .transpose()?;
    let access_expiry = if claims.exp > now {
        claims.exp
    } else {
        now + response.expires_in
    };
    auth.access_token = Some(Token {
        value: response.access_token,
        expires_at: access_expiry,
        issued_at: claims.iat,
    });
    if let Some(refresh) = response.refresh_token {
        let expires_at = response
            .refresh_token_expires_in
            .map(|seconds| now + seconds)
            .or(inherited_refresh_expiry)
            .unwrap_or(now + 24 * 60 * 60);
        auth.refresh_token = Some(Token {
            value: refresh,
            expires_at,
            issued_at: Some(now),
        });
    }
    auth.tenant_id = claims.tid.clone().or_else(|| {
        client_info
            .as_ref()
            .map(|value| value.utid.clone())
            .filter(|value| !value.is_empty())
    });
    if let Some(info) = client_info.as_ref()
        && !info.uid.is_empty()
        && !info.utid.is_empty()
    {
        auth.home_account_id = Some(format!("{}.{}", info.uid, info.utid));
    }
    auth.anchor_mailbox = match (claims.puid.as_deref(), auth.tenant_id.as_deref()) {
        (Some(puid), Some(tenant)) if !puid.is_empty() && !tenant.is_empty() => {
            Some(format!("PUID:{puid}@{tenant}"))
        }
        _ => auth.anchor_mailbox.clone(),
    };
    Ok(())
}

fn decode_client_info(value: &str) -> anyhow::Result<ClientInfo> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .context("client_info is not valid base64url")?;
    serde_json::from_slice(&bytes).context("client_info is not valid JSON")
}

fn pkce_verifier() -> String {
    let mut bytes = [0u8; 64];
    for chunk in bytes.chunks_exact_mut(16) {
        chunk.copy_from_slice(Uuid::new_v4().as_bytes());
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        TokenResponse, authorization_code_from_redirect, decode_client_info, decode_jwt_claims,
        pkce_verifier, validate_token_response_identity,
    };
    use crate::session::AuthState;
    use base64::Engine;

    fn jwt(payload: &str) -> String {
        format!(
            "e30.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[test]
    fn decodes_routing_and_username_claims() {
        let claims = decode_jwt_claims(&jwt(
            r#"{"exp":123,"iat":100,"tid":"tenant","puid":"puid","upn":"u@example.com"}"#,
        ))
        .unwrap();
        assert_eq!(claims.exp, 123);
        assert!(claims.matches_username("U@example.com"));
        assert!(!claims.matches_username("u@different.example"));
        assert_eq!(claims.tid.as_deref(), Some("tenant"));
    }

    #[test]
    fn validates_interactive_redirect_state() {
        let redirect = url::Url::parse(
            "https://outlook.cloud.microsoft/mail/#code=secret-code&state=expected",
        )
        .unwrap();
        assert_eq!(
            authorization_code_from_redirect(&redirect, "expected")
                .unwrap()
                .as_str(),
            "secret-code"
        );
        assert!(authorization_code_from_redirect(&redirect, "wrong").is_err());
    }

    #[test]
    fn decodes_msal_client_info() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"uid":"user","utid":"tenant"}"#);
        let info = decode_client_info(&encoded).unwrap();
        assert_eq!(info.uid, "user");
        assert_eq!(info.utid, "tenant");
    }

    #[test]
    fn rejects_token_response_for_a_different_home_account() {
        let client_info = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"uid":"other-user","utid":"tenant"}"#);
        let response = TokenResponse {
            access_token: jwt(r#"{"exp":4102444800,"tid":"tenant","upn":"u@example.com"}"#),
            refresh_token: None,
            expires_in: 3600,
            refresh_token_expires_in: None,
            client_info: Some(client_info),
        };
        let auth = AuthState {
            home_account_id: Some("expected-user.tenant".into()),
            ..AuthState::default()
        };
        assert!(validate_token_response_identity(&auth, &response, Some("u@example.com")).is_err());
    }

    #[test]
    fn pkce_verifier_has_valid_rfc7636_shape() {
        let verifier = pkce_verifier();
        assert!((43..=128).contains(&verifier.len()));
        assert!(
            verifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }
}

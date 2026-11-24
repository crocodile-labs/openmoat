//! A Google Cloud service account access token limited to named scopes (IAM
//! Service Account Credentials API, `projects.serviceAccounts.generateAccessToken`:
//! `scope` required, `lifetime` up to one hour by default). The caller is the
//! person's own credential file: `authorized_user` (what `gcloud auth
//! application-default login` writes), exchanged with its refresh token, or a
//! `service_account` key, exchanged with a signed JWT (RFC 7523). Both go to
//! Google's token endpoint only, whatever `token_uri` the file names.

use anyhow::{Context as _, Result, bail};
use openmoat_core::mint::{GCP_CREDENTIALS, Gcp};
use zeroize::Zeroizing;

use super::encode::form;
use super::{Minted, Request, Response, expiry, field, json, refused, rsa};

/// Google's OAuth token endpoint.
pub const TOKEN_HOST: &str = "oauth2.googleapis.com";
/// The IAM Service Account Credentials API.
pub const IAM_HOST: &str = "iamcredentials.googleapis.com";
/// The scope the caller's own token needs for `generateAccessToken`.
const CALLER_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const FORM: &str = "application/x-www-form-urlencoded";

/// The request that turns the credential file `file` (its JSON) into the
/// caller's own access token, at `now_s`.
pub fn caller_request(file: &str, now_s: i64) -> Result<Request> {
    let file = json(file.as_bytes()).context("reading the Google credential file")?;
    let body = match file.get("type").and_then(|t| t.as_str()) {
        Some("authorized_user") => Zeroizing::new(form(&[
            ("client_id", &field(&file, "client_id")?),
            ("client_secret", &field(&file, "client_secret")?),
            ("grant_type", "refresh_token"),
            ("refresh_token", &field(&file, "refresh_token")?),
        ])),
        Some("service_account") => {
            let key = rsa::key(&field(&file, "private_key")?)?;
            let claims = serde_json::json!({
                "iss": field(&file, "client_email")?.as_str(),
                "scope": CALLER_SCOPE,
                "aud": format!("https://{TOKEN_HOST}/token"),
                "iat": now_s,
                "exp": now_s + 3600,
            });
            let assertion = rsa::jwt(&key, &claims.to_string())?;
            Zeroizing::new(form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ]))
        }
        _ => bail!("the Google credential file is neither `authorized_user` nor `service_account`"),
    };
    Ok(Request {
        method: "POST",
        path: "/token".into(),
        headers: Vec::new(),
        content_type: FORM,
        body: Zeroizing::new(body.as_bytes().to_vec()),
    })
}

/// The caller's access token in the token endpoint's answer.
pub fn caller_token(response: &Response) -> Result<Zeroizing<String>> {
    let body = json(&response.body);
    if response.status != 200 {
        let code = body
            .ok()
            .and_then(|b| b.get("error").and_then(|e| e.as_str()).map(str::to_owned));
        return Err(refused("Google's token endpoint", response, code));
    }
    field(&body?, "access_token")
}

/// The `generateAccessToken` request for `gcp`, of `lifetime_secs`, made
/// with the caller's `token`.
pub fn request(gcp: &Gcp, lifetime_secs: u64, token: &str) -> Request {
    let body = serde_json::json!({
        "scope": gcp.scopes,
        "lifetime": format!("{lifetime_secs}s"),
    });
    Request {
        method: "POST",
        path: format!(
            "/v1/projects/-/serviceAccounts/{}:generateAccessToken",
            gcp.service_account
        ),
        headers: vec![("Authorization", Zeroizing::new(format!("Bearer {token}")))],
        content_type: "application/json",
        body: Zeroizing::new(body.to_string().into_bytes()),
    }
}

/// The token and its expiry in `generateAccessToken`'s answer.
pub fn parse(response: &Response) -> Result<Minted> {
    let body = json(&response.body);
    if response.status != 200 {
        let status = body.ok().and_then(|b| {
            b.pointer("/error/status")
                .and_then(|s| s.as_str())
                .map(str::to_owned)
        });
        return Err(refused("Google IAM", response, status));
    }
    let body = body?;
    let token = field(&body, "accessToken")?;
    Ok(Minted {
        expires_ms: expiry(&body, "expireTime")?,
        masked: vec![token.clone()],
        value: token,
    })
}

/// Mint one token of `lifetime_secs` at `now` (ms).
pub fn mint(
    gcp: &Gcp,
    (now, lifetime_secs): (i64, u64),
    read: &dyn Fn(&str) -> Result<Zeroizing<String>>,
    send: &dyn Fn(&str, &Request) -> Result<Response>,
) -> Result<Minted> {
    let file = read(gcp.credentials.as_deref().unwrap_or(GCP_CREDENTIALS))?;
    let caller = caller_token(&send(TOKEN_HOST, &caller_request(&file, now / 1000)?)?)?;
    parse(&send(IAM_HOST, &request(gcp, lifetime_secs, &caller))?)
}

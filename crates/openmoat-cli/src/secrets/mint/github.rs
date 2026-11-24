//! A GitHub App installation access token, narrowed to named repositories
//! and permissions (GitHub REST, "Create an installation access token for an
//! app": `POST /app/installations/{installation_id}/access_tokens`, signed in
//! with a JWT; the token expires one hour after it is made).

use anyhow::{Result, bail};
use openmoat_core::mint::GithubApp;
use zeroize::Zeroizing;

use super::{Minted, Request, Response, expiry, field, json, refused, rsa};

/// GitHub's API host.
pub const HOST: &str = "api.github.com";

/// The JWT's claims (GitHub, "Generating a JSON Web Token for a GitHub App"):
/// issued a minute ago against clock drift, valid nine minutes (at most ten).
pub fn claims(app: &str, now_s: i64) -> String {
    // A numeric App ID goes as a number, a client ID as a string.
    let iss = if app.bytes().all(|b| b.is_ascii_digit()) {
        app.to_owned()
    } else {
        serde_json::Value::from(app).to_string()
    };
    format!(
        "{{\"iat\":{},\"exp\":{},\"iss\":{iss}}}",
        now_s - 60,
        now_s + 540
    )
}

/// The request that mints the token, signed in with `jwt`.
pub fn request(app: &GithubApp, jwt: &str) -> Request {
    let body = serde_json::json!({
        "repositories": app.repositories,
        "permissions": app.permissions,
    });
    Request {
        method: "POST",
        path: format!("/app/installations/{}/access_tokens", app.installation),
        headers: vec![
            (
                "Accept",
                Zeroizing::new("application/vnd.github+json".into()),
            ),
            ("Authorization", Zeroizing::new(format!("Bearer {jwt}"))),
            ("X-GitHub-Api-Version", Zeroizing::new("2022-11-28".into())),
        ],
        content_type: "application/json",
        body: Zeroizing::new(body.to_string().into_bytes()),
    }
}

/// The token and its expiry in GitHub's answer; refused when GitHub granted a
/// permission the policy did not ask for.
pub fn parse(app: &GithubApp, response: &Response) -> Result<Minted> {
    let body = json(&response.body);
    if response.status != 201 {
        let message = body
            .ok()
            .and_then(|b| b.get("message").and_then(|m| m.as_str()).map(str::to_owned));
        return Err(refused("GitHub", response, message));
    }
    let body = body?;
    if let Some(granted) = body.get("permissions").and_then(|p| p.as_object())
        && let Some(extra) = granted.keys().find(|k| !app.permissions.contains_key(*k))
    {
        bail!("GitHub granted permission `{extra}`, which the policy does not ask for");
    }
    let token = field(&body, "token")?;
    Ok(Minted {
        expires_ms: expiry(&body, "expires_at")?,
        masked: vec![token.clone()],
        value: token,
    })
}

/// Mint one token at `now` (ms): sign the JWT with the App's key, ask GitHub.
pub fn mint(
    app: &GithubApp,
    now: i64,
    read: &dyn Fn(&str) -> Result<Zeroizing<String>>,
    send: &dyn Fn(&str, &Request) -> Result<Response>,
) -> Result<Minted> {
    let key = rsa::key(&read(&app.key)?)?;
    let jwt = rsa::jwt(&key, &claims(&app.app, now / 1000))?;
    let response = send(HOST, &request(app, &jwt))?;
    parse(app, &response)
}

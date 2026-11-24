//! `mint` sources (ADR-118): short-lived, narrowed credentials the proxy
//! makes from one the person holds, through each provider's official call.
//!
//! | Provider | Call | Narrowed to | Lifetime |
//! |---|---|---|---|
//! | `github-app` | `POST /app/installations/{id}/access_tokens` | named repositories and permissions | 1 hour (GitHub's) |
//! | `aws-sts` | STS `AssumeRole` with an inline session policy | named actions on named resources | 15m to 12h |
//! | `gcp` | IAM Credentials `generateAccessToken` | named OAuth scopes | 1m to 1h |
//!
//! The person's own credential (the App's key, the AWS keys, the Google
//! credential file) is read by this process only, outside every sandbox,
//! each time a value is minted, and is never put in a request to anything but
//! the provider's own endpoint. A minted value goes into the broker like any
//! other; it is renewed before it ends ([`super::Refresher`]), and the
//! request a value past its end would go into is refused. The calls go out
//! from this process over the system's trust roots (`remote/https.rs`), not
//! through the agent's proxy, whose policy is the agent's. Errors name the
//! provider's status and error code, never a value or a body.

use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::mint::MintSource;
use zeroize::Zeroizing;

use super::command::Answer;
use crate::remote::https::{Client, Request, Response};

mod aws;
pub mod encode;
mod gcp;
mod github;
mod rsa;
mod sigv4;

/// How long one provider call may take.
const TIMEOUT: Duration = Duration::from_secs(30);
/// An answer that ends sooner than this is as good as expired.
const MIN_ANSWER_MS: i64 = 10_000;

/// Sends one request to a provider's host; the tests answer from fixtures.
pub trait Transport: Send + Sync {
    /// Send `request` to `host` over HTTPS.
    fn send(&self, host: &str, request: &Request) -> Result<Response>;
}

/// The real transport: HTTPS with the system's trust roots.
struct Https;

impl Transport for Https {
    fn send(&self, host: &str, request: &Request) -> Result<Response> {
        Client::new(host)?.send(request, TIMEOUT)
    }
}

/// What one provider call made: the value, when it ends, and every part of
/// it the audit log must mask as well.
pub struct Minted {
    pub value: Zeroizing<String>,
    pub expires_ms: i64,
    pub masked: Vec<Zeroizing<String>>,
}

/// A `mint` source made ready: what it mints and how.
pub struct Minter {
    id: String,
    source: MintSource,
    home: String,
    transport: Box<dyn Transport>,
    now_ms: fn() -> i64,
}

impl Minter {
    /// The minter of secret `id`; `home` is the person's home in slash form.
    pub fn prepare(id: &str, source: &MintSource, home: &str) -> Self {
        Self {
            id: id.to_owned(),
            source: source.clone(),
            home: home.trim_end_matches('/').to_owned(),
            transport: Box::new(Https),
            now_ms: crate::time::now_ms,
        }
    }

    /// The same minter, sending through `transport` with the clock `now_ms`.
    #[cfg(test)]
    pub fn with(self, transport: Box<dyn Transport>, now_ms: fn() -> i64) -> Self {
        Self {
            transport,
            now_ms,
            ..self
        }
    }

    /// The file at `path` (absolute or `~/…`), as text, zeroed when dropped.
    fn read(&self, path: &str) -> Result<Zeroizing<String>> {
        let full = match path.strip_prefix("~/") {
            Some(rest) => format!("{}/{rest}", self.home),
            None => path.to_owned(),
        };
        Ok(Zeroizing::new(
            std::fs::read_to_string(&full).with_context(|| format!("reading {path}"))?,
        ))
    }
}

impl super::Fetch for Minter {
    fn id(&self) -> &str {
        &self.id
    }

    fn refresh_before(&self) -> Duration {
        Duration::from_secs(self.source.refresh_before_secs())
    }

    fn time_limit(&self) -> Duration {
        TIMEOUT
    }

    /// Mint a value now. Its lifetime is the shorter of what the policy asks
    /// and what the provider gave.
    fn fetch(&self) -> Result<Answer> {
        let now = (self.now_ms)();
        let send = |host: &str, request: &Request| self.transport.send(host, request);
        let read = |path: &str| self.read(path);
        let lifetime = self.source.lifetime_secs();
        let minted = match &self.source {
            MintSource::GithubApp(app) => github::mint(app, now, &read, &send),
            MintSource::AwsSts(sts) => aws::mint((&self.id, sts), (now, lifetime), &read, &send),
            MintSource::Gcp(gcp) => gcp::mint(gcp, (now, lifetime), &read, &send),
        }
        .with_context(|| format!("minting with {}", self.source.provider()))?;
        answer(minted, now, lifetime)
    }
}

/// The answer for `minted` at `now`: used for the shorter of `asked_secs`
/// and the time left before the provider's expiry.
pub fn answer(minted: Minted, now: i64, asked_secs: u64) -> Result<Answer> {
    let left = minted.expires_ms - now;
    ensure!(
        left >= MIN_ANSWER_MS,
        "the provider answered with a credential that expires in {}s",
        left.max(0) / 1000
    );
    let left = Duration::from_millis(u64::try_from(left).unwrap_or(0));
    Ok(Answer {
        value: minted.value,
        lifetime: left.min(Duration::from_secs(asked_secs)),
        masked: minted.masked,
    })
}

/// What a provider's call failed with: its status, and its own error code or
/// message when the body names one; never the body itself.
pub fn refused(provider: &str, response: &Response, code: Option<String>) -> anyhow::Error {
    let code = code
        .map(|c| {
            c.chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect::<String>()
        })
        .map_or_else(String::new, |c| format!(": {c}"));
    anyhow::Error::msg(format!(
        "{provider} refused the minting request with HTTP {}{code}",
        response.status
    ))
}

/// The JSON object in `body`.
pub fn json(body: &[u8]) -> Result<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("the answer is not JSON")?;
    if !value.is_object() {
        bail!("the answer is not a JSON object");
    }
    Ok(value)
}

/// The string field `name` of `value`, zeroed when dropped.
pub fn field(value: &serde_json::Value, name: &str) -> Result<Zeroizing<String>> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| Zeroizing::new(s.to_owned()))
        .with_context(|| format!("the answer has no `{name}`"))
}

/// The expiry field `name` of `value`, in ms since the epoch.
pub fn expiry(value: &serde_json::Value, name: &str) -> Result<i64> {
    let text = field(value, name)?;
    encode::expiry_ms(&text).with_context(|| format!("the answer's `{name}` is not a UTC time"))
}

#[cfg(test)]
mod tests;

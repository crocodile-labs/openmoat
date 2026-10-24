//! Per-session proxy credentials (ADR-027).
//!
//! In session mode every request carries a `Basic` proxy credential whose user
//! name is the audit session id and whose password is a random token only that
//! session's processes were given. Clients send it when their proxy URL has
//! userinfo (`http://<session>:<token>@127.0.0.1:<port>`). A request without a
//! valid credential is refused (`proxy-session`) before its host is decided.
//!
//! The session id then selects the session's taint ([`TaintLookup`]) and its
//! share of the connections (`slots.rs`).

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use openmoat_core::Taint;
use zeroize::Zeroizing;

/// Rule id for a request refused for its session: no valid credential, the
/// session's connection share used up, or its history unreadable.
pub const RULE_SESSION: &str = "proxy-session";

/// Shortest token a [`Credential`] accepts, in characters.
pub const MIN_TOKEN_LEN: usize = 32;

/// Longest session id a [`Credential`] accepts.
const MAX_SESSION_LEN: usize = 128;

/// One session's credential: its audit session id and its token.
pub struct Credential {
    session: String,
    token: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token never appears in a log line or panic message.
        f.debug_struct("Credential")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

/// Why a [`Credential`] cannot be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// The session id is empty, too long, or holds a character other than
    /// ASCII letters, digits, `.`, `_` and `-`.
    #[error("a session id is 1 to 128 ASCII letters, digits, `.`, `_` or `-`")]
    Session,
    /// The token is shorter than [`MIN_TOKEN_LEN`] or holds such a character.
    #[error("a session token is at least 32 ASCII letters, digits, `.`, `_` or `-`")]
    Token,
}

/// Characters that need no escaping in a URL's userinfo or a Basic credential.
fn plain(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Credential {
    /// The credential of `session`, which presents `token`.
    pub fn new(session: &str, token: &[u8]) -> Result<Self, CredentialError> {
        if session.is_empty() || session.len() > MAX_SESSION_LEN || !plain(session.as_bytes()) {
            return Err(CredentialError::Session);
        }
        if token.len() < MIN_TOKEN_LEN || !plain(token) {
            return Err(CredentialError::Token);
        }
        Ok(Self {
            session: session.to_owned(),
            token: Zeroizing::new(token.to_vec()),
        })
    }

    /// The audit session id.
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    /// `http://<session>:<token>@<addr>`: what the session's `HTTP_PROXY` and
    /// `HTTPS_PROXY` hold. Zeroed when dropped.
    #[must_use]
    pub fn proxy_url(&self, addr: SocketAddr) -> Zeroizing<String> {
        let token = String::from_utf8_lossy(&self.token);
        Zeroizing::new(format!("http://{}:{token}@{addr}", self.session))
    }
}

/// What a session was exposed to, read when one of its requests is decided.
/// The CLI reads it from the audit log; tests pass a fixed map.
pub trait TaintLookup: Send + Sync {
    /// The taint of `session`. An error refuses the request: without the
    /// session's history the proxy cannot tell whether it read a secret.
    fn taint(&self, session: &str) -> Result<Taint, String>;

    /// A mark that changes whenever a taint may have (the audit log's newest
    /// event id), so a taint looked up before it changed is not used again.
    /// `None` when there is none or it cannot be read (the audit log will not
    /// open): the taint is then looked up again every time, since a new event
    /// could not be seen.
    fn version(&self) -> Option<i64> {
        None
    }
}

/// Why a request's credential is refused. The reply does not say whether the
/// session id or the token was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// No `Proxy-Authorization` header.
    #[error("this proxy serves sessions only: the request carries no session credential")]
    Missing,
    /// More than one header, a scheme other than `Basic`, or bad base64.
    #[error("the session credential is malformed")]
    Malformed,
    /// No session has this id and token.
    #[error("the session credential is not valid")]
    Invalid,
}

/// A taint as looked up: when, at which [`TaintLookup::version`], and what.
type Looked = (Instant, Option<i64>, Taint);

/// Session mode: the credentials the proxy accepts and where their taint is read.
pub struct Sessions<'a> {
    credentials: Vec<Credential>,
    taint: &'a dyn TaintLookup,
    /// The last taint looked up per session, when, and at which
    /// [`TaintLookup::version`]: what the open connections are checked against
    /// again ([`Sessions::taint_within`]).
    recent: Mutex<HashMap<String, Looked>>,
}

impl fmt::Debug for Sessions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions")
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl<'a> Sessions<'a> {
    /// Accept `credentials`; look each session's taint up in `taint`.
    #[must_use]
    pub fn new(credentials: Vec<Credential>, taint: &'a dyn TaintLookup) -> Self {
        Self {
            credentials,
            taint,
            recent: Mutex::new(HashMap::new()),
        }
    }

    /// The session that `headers` (every `Proxy-Authorization` value of the
    /// request) authenticate. Every credential is compared in full, in time
    /// that does not depend on where a guess first differs.
    pub fn verify<T: AsRef<[u8]>>(&self, headers: &[T]) -> Result<&str, AuthError> {
        let value = match headers {
            [] => return Err(AuthError::Missing),
            [one] => one.as_ref(),
            _ => return Err(AuthError::Malformed),
        };
        let decoded = basic(value).ok_or(AuthError::Malformed)?;
        let colon = decoded
            .iter()
            .position(|b| *b == b':')
            .ok_or(AuthError::Malformed)?;
        let (session, token) = (&decoded[..colon], &decoded[colon + 1..]);
        let mut found = None;
        for credential in &self.credentials {
            let id = constant_time_eq(credential.session.as_bytes(), session);
            let secret = constant_time_eq(&credential.token, token);
            if id & secret {
                found = Some(credential.session.as_str());
            }
        }
        found.ok_or(AuthError::Invalid)
    }

    /// The taint of `session`, from the lookup.
    pub fn taint(&self, session: &str) -> Result<Taint, String> {
        // the mark before the lookup: an event recorded during it changes it
        let version = self.taint.version();
        let taint = self.taint.taint(session)?;
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        recent.insert(session.to_owned(), (Instant::now(), version, taint.clone()));
        Ok(taint)
    }

    /// The taint of `session` as looked up at most `max_age` ago and with no
    /// event recorded since ([`TaintLookup::version`]), else looked up again;
    /// always looked up again while there is no version to compare.
    /// Each open connection of a session is checked against its taint every so
    /// often; this keeps that to one lookup per new event, at most one per
    /// `max_age`, for the whole session. A new connection uses [`Self::taint`].
    pub fn taint_within(&self, session: &str, max_age: Duration) -> Result<Taint, String> {
        let version = self.taint.version();
        {
            let recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some((at, seen, taint)) = recent.get(session)
                && at.elapsed() < max_age
                && version.is_some()
                && *seen == version
            {
                return Ok(taint.clone());
            }
        }
        self.taint(session)
    }
}

/// The decoded `user:password` of a `Basic` credential (RFC 7617); the scheme
/// is matched without regard to case.
fn basic(value: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let value = value.trim_ascii();
    let space = value.iter().position(u8::is_ascii_whitespace)?;
    let (scheme, rest) = value.split_at(space);
    if !scheme.eq_ignore_ascii_case(b"basic") {
        return None;
    }
    base64(rest.trim_ascii())
}

/// Whether `a` and `b` are equal, in time that depends only on their lengths.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a
        .iter()
        .zip(b)
        .fold(0u8, |acc, (x, y)| acc | std::hint::black_box(x ^ y));
    std::hint::black_box(diff) == 0
}

/// Standard base64 (RFC 4648 §4), padding optional; `None` on any other byte.
fn base64(input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let data = input
        .strip_suffix(b"==")
        .or_else(|| input.strip_suffix(b"="))
        .unwrap_or(input);
    let padded = data.len() != input.len();
    if data.is_empty() || data.len() % 4 == 1 || (padded && !input.len().is_multiple_of(4)) {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() / 4 * 3 + 2));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in data {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests;

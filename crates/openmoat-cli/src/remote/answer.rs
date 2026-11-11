//! A person's answer to a request (ADR-078 Decision 1.4) and the buttons that
//! carry it (Decision 3.3).

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use super::request::Request;
use super::{hex, verify_hex};
use crate::proxy_session::Key;

/// Signed in front of every answer.
const ANSWER_DOMAIN: &[u8] = b"openmoat-remote-answer-v1\n";
/// Signed in front of every button's tag.
const BUTTON_DOMAIN: &[u8] = b"openmoat-remote-button-v1\n";
const VERSION: u32 = 1;
/// Bytes of a button's tag (64 bits), so the whole button stays short: it is
/// a button's data, or a reply code an approver sends back.
const TAG_BYTES: usize = 8;
/// The length of every button's data: verdict, dot, 32-digit id, dot, tag.
pub const BUTTON_LEN: usize = 1 + 1 + 32 + 1 + TAG_BYTES * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approve,
    Deny,
}

impl Verdict {
    fn letter(self) -> char {
        match self {
            Self::Approve => 'a',
            Self::Deny => 'd',
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Self::Approve => "approved",
            Self::Deny => "denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub version: u32,
    /// The request's id.
    pub id: String,
    /// The request's digest.
    pub digest: String,
    pub verdict: Verdict,
    /// The approver id that answered, qualified with the channel's name
    /// (`<channel>:<user id>`, [`super::channel::approver_id`]).
    pub approver: String,
    /// The channel the answer came over.
    pub channel: String,
    pub answered_ms: i64,
    /// The request's expiry: the answer holds until then.
    pub expires_ms: i64,
    #[serde(default)]
    pub mac: String,
}

impl Answer {
    /// `approver`'s `verdict` on `request` over `channel` at `now_ms`, signed.
    pub fn signed(
        key: &Key,
        request: &Request,
        (verdict, approver, channel): (Verdict, &str, &str),
        now_ms: i64,
    ) -> Result<Self> {
        let mut answer = Self {
            version: VERSION,
            id: request.id.clone(),
            digest: request.digest.clone(),
            verdict,
            approver: approver.to_owned(),
            channel: channel.to_owned(),
            answered_ms: now_ms,
            expires_ms: request.expires_ms,
            mac: String::new(),
        };
        answer.mac = hex(&key.mac(ANSWER_DOMAIN, &answer.signed_bytes()?));
        Ok(answer)
    }

    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.mac.clear();
        serde_json::to_vec(&unsigned).context("encoding a remote answer")
    }

    /// Whether `key` signed this answer and it answers exactly `request`.
    pub fn answers(&self, key: &Key, request: &Request) -> bool {
        self.version == VERSION
            && self.id == request.id
            && self.digest == request.digest
            && self.expires_ms == request.expires_ms
            && self
                .signed_bytes()
                .is_ok_and(|bytes| verify_hex(&self.mac, &key.mac(ANSWER_DOMAIN, &bytes)))
    }
}

fn tag(key: &Key, verdict: Verdict, request: &Request) -> String {
    let message = format!("{}\n{}\n{}", verdict.letter(), request.id, request.digest);
    hex(&key.mac(BUTTON_DOMAIN, message.as_bytes())[..TAG_BYTES])
}

/// The data of the button that gives `verdict` on `request`:
/// `<a|d>.<id>.<tag>`, [`BUTTON_LEN`] bytes.
pub fn button(key: &Key, verdict: Verdict, request: &Request) -> String {
    format!(
        "{}.{}.{}",
        verdict.letter(),
        request.id,
        tag(key, verdict, request)
    )
}

/// A button's verdict and request id, when it has the shape [`button`] gives;
/// whether its tag holds is [`button_holds`].
pub fn parse_button(data: &str) -> Option<(Verdict, &str, &str)> {
    let mut parts = data.split('.');
    let verdict = match parts.next()? {
        "a" => Verdict::Approve,
        "d" => Verdict::Deny,
        _ => return None,
    };
    let id = parts.next()?;
    let tag = parts.next()?;
    if parts.next().is_some() || id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((verdict, id, tag))
}

/// Whether `given` is the tag OpenMoat put on `verdict`'s button for `request`.
pub fn button_holds(key: &Key, verdict: Verdict, request: &Request, given: &str) -> bool {
    openmoat_proxy::constant_time_eq(given.as_bytes(), tag(key, verdict, request).as_bytes())
}

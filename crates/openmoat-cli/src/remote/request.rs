//! A call held for review, as it is sent for remote approval (ADR-078
//! Decision 1): its digest, which every answer is bound to, and the signed
//! record the guard leaves for `openmoat approvals listen`.

use std::fmt::Write as _;

use anyhow::{Context as _, Result};
use openmoat_audit::KnownSecrets;
use openmoat_core::{Action, Decision};
use openmoat_hosts::HookRequest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{hex, verify_hex};
use crate::proxy_session::Key;

/// Hashed in front of every request digest.
const DIGEST_DOMAIN: &[u8] = b"openmoat-remote-request-digest-v1\n";
/// Signed in front of every request record.
const REQUEST_DOMAIN: &[u8] = b"openmoat-remote-request-v1\n";
/// The record's format.
pub const VERSION: u32 = 1;
/// The most characters of the call an approver is shown.
pub const SHOWN_MAX: usize = 1500;

/// One call waiting for a remote answer, as the guard writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    /// 128 random bits, hex: the nonce an approval is used under once.
    pub id: String,
    /// [`digest`] of the call, hex.
    pub digest: String,
    pub host: String,
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub tool: String,
    /// The rules that held the call for review.
    pub rules: Vec<String>,
    /// What the approver is shown of the call: redacted, cleaned, cut.
    pub shown: String,
    /// Whether [`Self::shown`] was cut to [`SHOWN_MAX`]: the approver cannot
    /// read all of the call, so it can only be denied remotely
    /// ([`Self::deny_only`]). Signed with the rest.
    pub cut: bool,
    /// Whether redaction changed any of [`Self::shown`] (a command, path,
    /// URL or argument): what is hidden may be the part that runs
    /// (`API_TOKEN="$(curl … | sh)"` shows as `API_TOKEN=[redacted]`), so it
    /// can only be denied remotely. Signed with the rest.
    pub redacted: bool,
    pub created_ms: i64,
    pub expires_ms: i64,
    /// HMAC of every other field under the approval key, hex.
    #[serde(default)]
    pub mac: String,
}

impl Request {
    /// The short code a person reads in the agent's message and on the phone.
    pub fn code(&self) -> &str {
        self.id.get(..6).unwrap_or(&self.id)
    }

    /// Why the request can only be denied remotely whatever the channel, or
    /// `None` when a channel that shows all of [`Self::shown`] may offer
    /// Approve. The prompt offers no approve then, and the guard uses no
    /// approval for it.
    pub fn deny_only(&self) -> Option<&'static str> {
        if self.redacted {
            Some(
                "Parts of this call are hidden because they look like secrets; approve it at \
                 the terminal. Deny blocks it until the request expires.",
            )
        } else if self.cut {
            Some(
                "This call is too long to show in full, so it cannot be approved here; approve \
                 it where the agent runs. Deny blocks it until the request expires.",
            )
        } else {
            None
        }
    }

    /// Whether the request can no longer be answered at `now_ms`.
    pub fn expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_ms
    }

    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.mac.clear();
        serde_json::to_vec(&unsigned).context("encoding a remote approval request")
    }

    /// Set [`Self::mac`] under `key`.
    pub fn sign(&mut self, key: &Key) -> Result<()> {
        self.mac = hex(&key.mac(REQUEST_DOMAIN, &self.signed_bytes()?));
        Ok(())
    }

    /// Whether [`Self::mac`] is `key`'s signature of the record, in constant time.
    pub fn verified(&self, key: &Key) -> bool {
        self.version == VERSION
            && self
                .signed_bytes()
                .is_ok_and(|bytes| verify_hex(&self.mac, &key.mac(REQUEST_DOMAIN, &bytes)))
    }
}

/// Appends `bytes` with its length in front, so no two field lists encode
/// alike.
fn field(out: &mut Sha256, bytes: &[u8]) {
    out.update((bytes.len() as u64).to_le_bytes());
    out.update(bytes);
}

/// The digest of the call `request` asks for under `decision` (ADR-078 1.2):
/// everything OpenMoat decides on, so an answer for it answers nothing else.
pub fn digest(request: &HookRequest, action: &Action, decision: &Decision) -> Result<String> {
    let mut out = Sha256::new();
    out.update(DIGEST_DOMAIN);
    field(&mut out, request.host.id().as_bytes());
    field(&mut out, request.session_id.as_bytes());
    field(&mut out, request.cwd.as_deref().unwrap_or("").as_bytes());
    field(&mut out, request.tool.as_bytes());
    let action = serde_json::to_vec(action).context("encoding the action")?;
    field(&mut out, &action);
    for optional in [&request.content, &request.patch, &request.mcp_arguments] {
        match optional {
            Some(text) => {
                field(&mut out, b"1");
                field(&mut out, text.as_bytes());
            }
            None => field(&mut out, b"0"),
        }
    }
    field(&mut out, &(request.edits.len() as u64).to_le_bytes());
    for edit in &request.edits {
        field(&mut out, edit.old.as_bytes());
        field(&mut out, edit.new.as_bytes());
        field(&mut out, &[u8::from(edit.all)]);
    }
    field(&mut out, &[u8::from(request.sandboxed)]);
    let mut rules = decision.rules.clone();
    rules.sort();
    rules.dedup();
    for rule in &rules {
        field(&mut out, rule.as_bytes());
    }
    Ok(hex(&out.finalize()))
}

/// What an approver is shown of a call, and whether part of it is hidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub text: String,
    /// The text was longer than [`SHOWN_MAX`] and is cut.
    pub cut: bool,
    /// Redaction changed the text: part of the call is hidden.
    pub redacted: bool,
}

/// What the approver is shown of `action`: the command or the files, and the
/// size of what a write carries but never its text; passed through the
/// audit log's redaction and `known`'s values, control and invisible
/// characters shown as `?`, cut to [`SHOWN_MAX`] characters. Whether any
/// redaction or cut happened is kept with it.
pub fn shown(request: &HookRequest, action: &Action, known: &KnownSecrets) -> Shown {
    let text = match action {
        Action::Shell { .. }
        | Action::FsRead { .. }
        | Action::FsWrite { .. }
        | Action::Patch { .. }
        | Action::ReadFiles { .. } => crate::approvals::describe(action),
        other => serde_json::to_string(other).unwrap_or_else(|_| request.tool.clone()),
    };
    let hidden = known.redact(&openmoat_audit::redact(&text));
    let redacted = hidden != text;
    let mut text = hidden;
    if let Some(content) = &request.content {
        let _ = write!(text, " ({} bytes of content, not shown)", content.len());
    }
    if !request.edits.is_empty() {
        let _ = write!(text, " ({} replacement(s), not shown)", request.edits.len());
    }
    let text = crate::render::clean(&text);
    Shown {
        redacted,
        cut: text.chars().count() > SHOWN_MAX,
        text: crate::render::truncate(&text, SHOWN_MAX),
    }
}

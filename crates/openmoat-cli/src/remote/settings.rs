//! `~/.moat/remote/channel.json`: which channel answers, who may approve and
//! how long a request waits (ADR-078 Decisions 2.3 and 3). Signed with the
//! approval key, so a file written without the key is refused, and with it
//! every remote answer.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use super::{hex, verify_hex};
use crate::proxy_session::Key;

/// Signed in front of the settings.
const DOMAIN: &[u8] = b"openmoat-remote-settings-v1\n";
const VERSION: u32 = 1;
/// How long a request waits for an answer unless the person chose otherwise.
pub const DEFAULT_EXPIRY_S: u64 = 5 * 60;
/// The shortest and longest wait `connect --expires` accepts.
pub const MIN_EXPIRY_S: u64 = 60;
pub const MAX_EXPIRY_S: u64 = 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub version: u32,
    /// The channel's name, as [`super::Channel::name`] gives it.
    pub channel: String,
    /// The channel user ids whose answers count; empty approves nothing.
    pub approvers: Vec<String>,
    pub expiry_s: u64,
    #[serde(default)]
    pub mac: String,
}

impl Settings {
    /// New settings for `channel` with no approver yet.
    pub fn new(channel: &str, expiry_s: u64) -> Result<Self> {
        if !(MIN_EXPIRY_S..=MAX_EXPIRY_S).contains(&expiry_s) {
            bail!(
                "a request waits between {} and {} minutes",
                MIN_EXPIRY_S / 60,
                MAX_EXPIRY_S / 60
            );
        }
        Ok(Self {
            version: VERSION,
            channel: channel.to_owned(),
            approvers: Vec::new(),
            expiry_s,
            mac: String::new(),
        })
    }

    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.mac.clear();
        serde_json::to_vec(&unsigned).context("encoding the approval settings")
    }

    /// Whether `id` may approve.
    pub fn approver(&self, id: &str) -> bool {
        self.approvers.iter().any(|a| a == id)
    }

    /// The settings in `path`, refused unless `key` signed them and the
    /// expiry is in range.
    pub fn load(path: &Path, key: &Key) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let settings: Self = serde_json::from_str(&text)
            .with_context(|| format!("{} is not approval settings", path.display()))?;
        let signed = settings.signed_bytes()?;
        if settings.version != VERSION || !verify_hex(&settings.mac, &key.mac(DOMAIN, &signed)) {
            bail!(
                "{} is not signed with this machine's approval key, so no remote answer is \
                 accepted; run `openmoat approvals connect` again",
                path.display()
            );
        }
        if !(MIN_EXPIRY_S..=MAX_EXPIRY_S).contains(&settings.expiry_s) {
            bail!("{} sets an expiry out of range", path.display());
        }
        Ok(settings)
    }

    /// Sign with `key` and write to `path`, owner-only.
    pub fn save(&mut self, path: &Path, key: &Key) -> Result<()> {
        self.approvers.sort();
        self.approvers.dedup();
        self.mac = hex(&key.mac(DOMAIN, &self.signed_bytes()?));
        let mut text = serde_json::to_string_pretty(self).context("encoding the settings")?;
        text.push('\n');
        crate::home::write_private(path, text.as_bytes())
    }
}

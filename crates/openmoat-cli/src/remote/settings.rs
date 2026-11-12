//! The signed settings of remote approval (ADR-078 Decisions 2.3 and 3):
//!
//! - [`Settings`], `~/.moat/remote/settings.json`: which channel answers, who
//!   may approve and how long a request waits;
//! - [`ChannelSettings`], `~/.moat/remote/<channel>/settings.json`: the
//!   channel's account and the answers to its own `connect` questions.
//!
//! Both are signed with the approval key, so a file written without the key
//! is refused, and with it every remote answer.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::channel::{Options, local_id};
use super::{hex, verify_hex};
use crate::proxy_session::Key;

/// Signed in front of the settings.
const DOMAIN: &[u8] = b"openmoat-remote-settings-v1\n";
/// Signed in front of a channel's own settings.
const CHANNEL_DOMAIN: &[u8] = b"openmoat-remote-channel-settings-v1\n";
const VERSION: u32 = 1;
/// How long a request waits for an answer unless the person chose otherwise.
pub const DEFAULT_EXPIRY_S: u64 = 5 * 60;
/// The shortest and longest wait `connect --expires` accepts.
pub const MIN_EXPIRY_S: u64 = 60;
pub const MAX_EXPIRY_S: u64 = 60 * 60;

/// A record signed with the approval key: its `mac` covers every other field.
trait Signed: Serialize + DeserializeOwned + Clone {
    const DOMAIN: &'static [u8];
    fn version(&self) -> u32;
    fn mac(&mut self) -> &mut String;

    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.mac().clear();
        serde_json::to_vec(&unsigned).context("encoding the approval settings")
    }

    fn load(path: &Path, key: &Key) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut value: Self = serde_json::from_str(&text)
            .with_context(|| format!("{} is not approval settings", path.display()))?;
        let signed = value.signed_bytes()?;
        let mac = value.mac().clone();
        if value.version() != VERSION || !verify_hex(&mac, &key.mac(Self::DOMAIN, &signed)) {
            bail!(
                "{} is not signed with this machine's approval key, so no remote answer is \
                 accepted; run `openmoat approvals connect` again",
                path.display()
            );
        }
        Ok(value)
    }

    fn save(&mut self, path: &Path, key: &Key) -> Result<()> {
        let mac = hex(&key.mac(Self::DOMAIN, &self.signed_bytes()?));
        *self.mac() = mac;
        let mut text = serde_json::to_string_pretty(self).context("encoding the settings")?;
        text.push('\n');
        crate::home::write_private(path, text.as_bytes())
    }
}

/// Read strictly: a field this release does not know is refused at load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub version: u32,
    /// The connected channel's name, as its [`super::channel::Spec`] gives it.
    pub channel: String,
    /// The approver ids whose answers count, each `<channel>:<user id>` of
    /// the connected channel; empty approves nothing.
    pub approvers: Vec<String>,
    pub expiry_s: u64,
    #[serde(default)]
    pub mac: String,
}

impl Signed for Settings {
    const DOMAIN: &'static [u8] = DOMAIN;
    fn version(&self) -> u32 {
        self.version
    }
    fn mac(&mut self) -> &mut String {
        &mut self.mac
    }
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

    /// Whether the approver id `id` may approve.
    pub fn approver(&self, id: &str) -> bool {
        self.approvers.iter().any(|a| a == id)
    }

    /// The settings in `path`, refused unless `key` signed them, the expiry
    /// is in range and every approver is of the connected channel.
    pub fn load(path: &Path, key: &Key) -> Result<Self> {
        let settings = <Self as Signed>::load(path, key)?;
        if !(MIN_EXPIRY_S..=MAX_EXPIRY_S).contains(&settings.expiry_s) {
            bail!("{} sets an expiry out of range", path.display());
        }
        settings.check_approvers()?;
        Ok(settings)
    }

    fn check_approvers(&self) -> Result<()> {
        if let Some(other) = self
            .approvers
            .iter()
            .find(|a| local_id(&self.channel, a).is_none_or(str::is_empty))
        {
            bail!(
                "the approver `{}` is not of the connected channel {}",
                crate::render::clean(other),
                self.channel
            );
        }
        Ok(())
    }

    /// Sign with `key` and write to `path`, owner-only.
    pub fn save(&mut self, path: &Path, key: &Key) -> Result<()> {
        self.approvers.sort();
        self.approvers.dedup();
        self.check_approvers()?;
        <Self as Signed>::save(self, path, key)
    }
}

/// A channel's own settings, beside its credential.
/// Read strictly, and its options checked against the channel's fields
/// whenever the channel is opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSettings {
    pub version: u32,
    /// The channel's name, so one channel's file never serves another.
    pub channel: String,
    /// The account the credential belongs to, as the channel named it at `connect`.
    pub account: String,
    /// The answers to the channel's `connect` questions.
    #[serde(default)]
    pub options: Options,
    #[serde(default)]
    pub mac: String,
}

impl Signed for ChannelSettings {
    const DOMAIN: &'static [u8] = CHANNEL_DOMAIN;
    fn version(&self) -> u32 {
        self.version
    }
    fn mac(&mut self) -> &mut String {
        &mut self.mac
    }
}

impl ChannelSettings {
    pub fn new(channel: &str, account: String, options: Options) -> Self {
        Self {
            version: VERSION,
            channel: channel.to_owned(),
            account,
            options,
            mac: String::new(),
        }
    }

    /// The settings of `channel` in `path`, refused unless `key` signed them
    /// for that channel.
    pub fn load(path: &Path, key: &Key, channel: &str) -> Result<Self> {
        let settings = <Self as Signed>::load(path, key)?;
        if settings.channel != channel {
            bail!("{} belongs to another channel", path.display());
        }
        Ok(settings)
    }

    /// Sign with `key` and write to `path`, owner-only.
    pub fn save(&mut self, path: &Path, key: &Key) -> Result<()> {
        <Self as Signed>::save(self, path, key)
    }
}

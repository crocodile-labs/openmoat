//! Whether `openmoat approvals listen` is running (ADR-093): after every round
//! that polled the channel without an error, the listener writes
//! `~/.moat/remote/listening.json`, the connected channel's name and the time,
//! signed with the approval key. The guard waits for an answer only while
//! that beat is fresh, so with no listener it never waits.
//!
//! The beat cannot loosen anything: it only decides whether the guard waits,
//! and every answer is still checked as on the next try (signature, digest,
//! approver, expiry, single use). An agent cannot write it (`kernel-self`
//! denies writes under `~/.moat`) nor sign one (it cannot read the key); one
//! that could would only make the guard wait, within its limits.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::settings::Signed;
use super::store::Store;
use crate::proxy_session::Key;

/// Signed in front of every beat.
const DOMAIN: &[u8] = b"openmoat-remote-listening-v1\n";
const VERSION: u32 = 1;
const FILE: &str = "listening.json";
/// A beat older than this says nothing: the listener stopped or cannot reach
/// its channel. Several of its rounds fit in it (`listen` polls every 2 s
/// while the wait is on, each round bounded by the channel's own time limit).
pub const LIVE_MS: i64 = 15_000;
/// How far ahead of the guard's clock a beat may be, for two processes
/// reading the same clock a moment apart; a beat further ahead is not trusted.
const AHEAD_MS: i64 = 2_000;

/// One beat of the listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Beat {
    pub version: u32,
    /// The channel the listener answers on.
    pub channel: String,
    /// When it last completed a round.
    pub at_ms: i64,
    #[serde(default)]
    pub mac: String,
}

impl Signed for Beat {
    const DOMAIN: &'static [u8] = DOMAIN;
    fn version(&self) -> u32 {
        self.version
    }
    fn mac(&mut self) -> &mut String {
        &mut self.mac
    }
}

fn path(store: &Store) -> PathBuf {
    store.dir().join(FILE)
}

/// Write the beat of a listener on `channel` at `now_ms`.
pub fn beat(store: &Store, key: &Key, channel: &str, now_ms: i64) -> Result<()> {
    let mut beat = Beat {
        version: VERSION,
        channel: channel.to_owned(),
        at_ms: now_ms,
        mac: String::new(),
    };
    <Beat as Signed>::save(&mut beat, &path(store), key)
}

/// Remove the beat: the listener stops.
pub fn stop(store: &Store) {
    let _ = std::fs::remove_file(path(store));
}

/// Whether a listener on `channel` completed a round within [`LIVE_MS`] of
/// `now_ms`, by a beat `key` signed. Anything else (no file, a bad
/// signature, another channel, a stale or future beat) is `false`.
pub fn live(store: &Store, key: &Key, channel: &str, now_ms: i64) -> bool {
    read(&path(store), key).is_some_and(|b| {
        b.channel == channel
            && b.at_ms <= now_ms.saturating_add(AHEAD_MS)
            && now_ms.saturating_sub(b.at_ms) <= LIVE_MS
    })
}

fn read(path: &Path, key: &Key) -> Option<Beat> {
    <Beat as Signed>::load(path, key).ok()
}

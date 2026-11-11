//! How many snapshots a store keeps, and for how long (ADR-085 §5).

use anyhow::Result;

use super::lock::Held;
use super::{Listed, Store};

/// How old an object no snapshot holds must be before `gc` drops it.
const PRUNE_GRACE: &str = "1.hour.ago";

/// What a store keeps: the newest `keep` snapshots, none older than `max_age_ms`;
/// the newest one always.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub keep: usize,
    pub max_age_ms: i64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            keep: 50,
            max_age_ms: 14 * 24 * 60 * 60 * 1000,
        }
    }
}

impl Retention {
    /// The snapshots of `listed` (oldest first) this retention removes at `now_ms`.
    pub fn expired<'a>(&self, listed: &'a [Listed], now_ms: i64) -> Vec<&'a Listed> {
        let Some((_newest, older)) = listed.split_last() else {
            return Vec::new();
        };
        let over = listed.len().saturating_sub(self.keep.max(1));
        older
            .iter()
            .enumerate()
            .filter(|(i, s)| *i < over || now_ms.saturating_sub(s.ts_ms) > self.max_age_ms)
            .map(|(_, s)| s)
            .collect()
    }
}

impl Store {
    /// Remove what `retention` does not keep, then let git drop their files;
    /// the number removed. Under the store's lock, and besides `gc` drops
    /// only objects no snapshot holds that are older than [`PRUNE_GRACE`]: a
    /// take's objects written before its ref stay whatever else goes wrong.
    pub fn prune(&self, held: &Held, retention: Retention, now_ms: i64) -> Result<usize> {
        self.check_held(held)?;
        let listed = self.list()?;
        let expired = retention.expired(&listed, now_ms);
        for snapshot in &expired {
            self.git.output(
                &["update-ref", "-d", &snapshot.refname, &snapshot.commit],
                None,
            )?;
        }
        if !expired.is_empty() {
            self.git.output(
                &[
                    "-c",
                    "gc.reflogExpire=now",
                    "gc",
                    "--quiet",
                    &format!("--prune={PRUNE_GRACE}"),
                ],
                None,
            )?;
        }
        Ok(expired.len())
    }
}

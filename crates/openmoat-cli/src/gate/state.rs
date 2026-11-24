//! What the gate remembers between commands, in `~/.moat/gate.json`: the last
//! step whose code was taken (so no code is taken twice) and the times of
//! recent wrong codes (so they are rate-limited). `kernel-self` keeps agents
//! from writing it, as every file of the state directory.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

/// Wrong codes allowed within [`WINDOW_MS`]; the next attempt waits.
pub const MAX_FAILURES: usize = 5;

/// How long a wrong code counts against the limit.
pub const WINDOW_MS: i64 = 15 * 60 * 1000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The last step a code was taken for; only a later one is taken next.
    #[serde(default)]
    pub last_step: u64,
    /// When each wrong code within the window was typed (ms since the epoch).
    #[serde(default)]
    pub failures: Vec<i64>,
}

impl State {
    /// The state in `path`: the empty state when there is no file. A file that
    /// does not parse is refused rather than read as empty, since an empty
    /// state would take a used code again.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "reading {}: the gate's state does not parse; move it aside to start it again",
                    path.display()
                )
            }),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut text = serde_json::to_vec_pretty(self)?;
        text.push(b'\n');
        crate::home::write_private(path, &text)
    }

    /// Forget wrong codes older than the window.
    pub fn prune(&mut self, now_ms: i64) {
        self.failures
            .retain(|t| now_ms - *t < WINDOW_MS && *t <= now_ms);
    }

    /// When the next code may be typed, when the limit is reached at `now_ms`.
    pub fn locked_until(&self, now_ms: i64) -> Option<i64> {
        let recent: Vec<i64> = self
            .failures
            .iter()
            .copied()
            .filter(|t| now_ms - *t < WINDOW_MS && *t <= now_ms)
            .collect();
        if recent.len() < MAX_FAILURES {
            return None;
        }
        // The oldest of the last MAX_FAILURES leaves the window first.
        let mut sorted = recent;
        sorted.sort_unstable();
        sorted
            .get(sorted.len() - MAX_FAILURES)
            .map(|t| t + WINDOW_MS)
    }

    /// A wrong code at `now_ms`.
    pub fn failed(&mut self, now_ms: i64) {
        self.prune(now_ms);
        self.failures.push(now_ms);
    }

    /// A code taken for `step`.
    pub fn passed(&mut self, step: u64) {
        self.last_step = step;
        self.failures.clear();
    }
}

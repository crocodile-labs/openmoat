//! Standing grants that end: `openmoat allow --for` (ADR-007, amendment of
//! 2026-11-08).
//!
//! A rule or directory grant in the overlay may carry a [`Window`] under
//! `expires:`, keyed by its id. Outside its window the entry is left out when
//! the policy loads ([`super::Overlay::in_force`]): the call it allowed is
//! back to the policy's own decision. A window that cannot be read is outside,
//! so a hand edit that breaks one ends the grant rather than making it
//! permanent. The window starts when the grant was made, so a clock set back
//! before that also ends it, as for session grants ([`super::Grant::active`]).

use serde::{Deserialize, Serialize};

use crate::time;

/// The longest `--for`: a grant meant to last longer is a permanent one.
pub const MAX_SPAN_MS: i64 = 366 * 24 * 3_600_000;

/// When an overlay entry holds: from when it was granted until it ends, in
/// RFC 3339 UTC to the second, as [`time::rfc3339`] writes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "WindowText")]
pub struct Window {
    pub from: String,
    pub until: String,
}

/// What a window may be in the file: anything that is not a mapping with
/// readable times reads as a window that never holds, never as an error that
/// would stop the whole overlay from loading.
#[derive(Deserialize)]
#[serde(untagged)]
enum WindowText {
    Window {
        #[serde(default)]
        from: String,
        #[serde(default)]
        until: String,
    },
    Other(serde::de::IgnoredAny),
}

impl From<WindowText> for Window {
    fn from(text: WindowText) -> Self {
        match text {
            WindowText::Window { from, until } => Self { from, until },
            WindowText::Other(_) => Self {
                from: String::new(),
                until: String::new(),
            },
        }
    }
}

/// Where `now` falls in a [`Window`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// In force, ending at this time (milliseconds since the epoch).
    Holds { until_ms: i64 },
    /// Its end is past.
    Ended { until_ms: i64 },
    /// It starts after `now`: the clock was set back since it was granted.
    Early,
    /// A time in it cannot be read, or it ends before it starts.
    Unreadable,
}

impl Window {
    /// From `now_ms` for `span_ms`: the start rounded down to the second and
    /// the end rounded up, so it holds at least as long as asked.
    #[must_use]
    pub fn starting(now_ms: i64, span_ms: i64) -> Self {
        let end = now_ms.saturating_add(span_ms).saturating_add(999);
        Self {
            from: time::rfc3339(now_ms),
            until: time::rfc3339(end.div_euclid(1000) * 1000),
        }
    }

    /// Where `now_ms` falls in it.
    #[must_use]
    pub fn state(&self, now_ms: i64) -> State {
        match (
            time::parse_rfc3339(&self.from),
            time::parse_rfc3339(&self.until),
        ) {
            (Some(from), Some(until_ms)) if from < until_ms => {
                if now_ms < from {
                    State::Early
                } else if now_ms < until_ms {
                    State::Holds { until_ms }
                } else {
                    State::Ended { until_ms }
                }
            }
            _ => State::Unreadable,
        }
    }

    /// Whether the entry it belongs to is in force at `now_ms`.
    #[must_use]
    pub fn holds(&self, now_ms: i64) -> bool {
        matches!(self.state(now_ms), State::Holds { .. })
    }
}

/// How far ahead `openmoat status` and `doctor` look for grants that end soon.
pub const SOON_MS: i64 = 24 * 3_600_000;

/// One line on the standing grants of `overlay` not in force at `now_ms` and
/// those that end within [`SOON_MS`], for `openmoat status` and `doctor`;
/// `None` when there are neither.
#[must_use]
pub fn summary(overlay: &super::Overlay, now_ms: i64) -> Option<String> {
    let mut ended = Vec::new();
    let mut soon = Vec::new();
    for id in overlay.ids() {
        match overlay.expires.get(id).map(|w| w.state(now_ms)) {
            Some(State::Holds { until_ms }) if until_ms - now_ms <= SOON_MS => {
                soon.push(format!("{id} in {}", time::duration(until_ms - now_ms)));
            }
            None | Some(State::Holds { .. }) => {}
            Some(_) => ended.push(id),
        }
    }
    let ended = (!ended.is_empty()).then(|| {
        format!(
            "{} standing grant(s) expired and no longer apply ({}; `openmoat allow --prune` \
             removes them)",
            ended.len(),
            ended.join(", ")
        )
    });
    let soon = (!soon.is_empty()).then(|| format!("ending soon: {}", soon.join(", ")));
    let parts: Vec<String> = [ended, soon].into_iter().flatten().collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// The span `--for` takes ([`time::parse_span`]), at most [`MAX_SPAN_MS`].
pub fn parse_for(text: &str) -> anyhow::Result<i64> {
    use anyhow::Context as _;
    let span = time::parse_span(text).filter(|s| *s <= MAX_SPAN_MS);
    span.with_context(|| {
        format!(
            "cannot read `{text}` as a duration; use a number and s, m, h, d or w (30m, 2h, \
             3d, 1w), at most 366 days; leave out --for for a grant that lasts until you \
             remove it"
        )
    })
}

#[cfg(test)]
mod tests;

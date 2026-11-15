//! Verifying an export without the database it came from.
//!
//! Every line must hash to its own `hash`. Ids must rise. Where two lines have
//! consecutive ids, the second must link to the first. A jump in ids is a gap:
//! a filtered export leaves gaps, and so does deleting events from the log, and
//! the file alone cannot tell the two apart. Nothing in the file shows that its
//! newest events were dropped; comparing against a head hash recorded elsewhere
//! (the anchor) does.
//!
//! Version 2 lines also carry the audit key's MAC (ADR-100). Without the key
//! that made them, they are checked as version 1 lines and counted in
//! [`ExportReport::keyed_unchecked`]: the hash chain then shows that no event
//! was edited on its own, not that the file was not rewritten as a whole, since
//! anyone can recompute the hashes. With the key, each MAC must match, and once
//! a line's MAC has, every later line must carry one.

use serde::{Deserialize, Serialize};

use super::chain::{BreakKind, GENESIS};
use super::{EventId, ExportFormat, ExportedEvent};
use crate::ChainKey;

/// The first line that fails [`verify_export`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBreak {
    /// Line number in the file, from 1.
    pub line: usize,
    /// The event on that line, when the line could be read.
    pub id: Option<EventId>,
    /// Why it fails; [`BreakKind::Unreadable`] for a line that is not an export line.
    pub kind: BreakKind,
}

/// Whether the export reaches a head hash recorded earlier (the anchor).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorCheck {
    /// No anchor was given: the chain can be intact while its newest events
    /// were dropped, and nothing in the file shows it.
    #[default]
    NotAnchored,
    /// A verified event carries the anchor.
    Found,
    /// No verified event carries the anchor: events up to it were rewritten or
    /// dropped, or the export covers another log or window.
    Missing,
}

/// The outcome of [`verify_export`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReport {
    /// Events verified, not counting a broken line.
    pub events: u64,
    /// Id of the first verified event.
    pub first_id: Option<EventId>,
    /// Id of the last verified event.
    pub last_id: Option<EventId>,
    /// The first event is the first of its log's chain (`prev_hash` is [`GENESIS`]).
    pub from_genesis: bool,
    /// Places where ids skip: a filtered export, or events deleted from the log.
    pub gaps: u64,
    /// Hash of the last verified event; record it elsewhere and pass it as the
    /// anchor when checking a later export.
    pub head: Option<String>,
    /// Whether a verified event has the anchor hash the caller passed.
    pub anchor: AnchorCheck,
    /// The first broken line, if any. Lines after it are not read.
    pub broken: Option<ExportBreak>,
    /// Events whose audit-key MAC was checked with the key and matched.
    #[serde(default)]
    pub keyed: u64,
    /// Events that carry a MAC no key given here made: checked by their hash
    /// chain only.
    #[serde(default)]
    pub keyed_unchecked: u64,
}

/// Verify the text of an export, oldest line first, and stop at the first broken
/// line. Blank lines are skipped. `anchor` is a head hash recorded earlier;
/// [`ExportReport::anchor`] says whether a verified event carries it, and is
/// [`AnchorCheck::NotAnchored`] without one. No MAC is checked: see
/// [`verify_export_keyed`].
#[must_use]
pub fn verify_export(text: &str, anchor: Option<&str>) -> ExportReport {
    verify_export_keyed(text, anchor, None)
}

/// [`verify_export`], also checking the MAC of every line `key` made (its
/// `key_id` is the key's [`ChainKey::id`]).
#[must_use]
pub fn verify_export_keyed(
    text: &str,
    anchor: Option<&str>,
    key: Option<&ChainKey>,
) -> ExportReport {
    let mut report = ExportReport::default();
    let mut anchor_found = false;
    let mut previous: Option<ExportedEvent> = None;
    let key = key.map(|key| (key.id(), key));
    for (index, content) in text.lines().enumerate() {
        if content.trim().is_empty() {
            continue;
        }
        let line = index + 1;
        let event = serde_json::from_str::<ExportedEvent>(content)
            .ok()
            .filter(well_formed);
        let Some(event) = event else {
            report.broken = Some(ExportBreak {
                line,
                id: None,
                kind: BreakKind::Unreadable,
            });
            break;
        };
        let kind = check(&event, previous.as_ref(), &mut report).or_else(|| {
            let key = key.as_ref().map(|(id, key)| (id.as_str(), *key));
            check_mac(&event, key, &mut report)
        });
        if let Some(kind) = kind {
            report.broken = Some(ExportBreak {
                line,
                id: Some(event.id),
                kind,
            });
            break;
        }
        report.events += 1;
        report.last_id = Some(event.id);
        report.head = Some(event.hash.clone());
        anchor_found |= anchor == Some(event.hash.as_str());
        previous = Some(event);
    }
    report.anchor = match anchor {
        None => AnchorCheck::NotAnchored,
        Some(_) if anchor_found => AnchorCheck::Found,
        Some(_) => AnchorCheck::Missing,
    };
    report
}

/// A version 2 line has a MAC and a key id, a version 1 line neither.
fn well_formed(event: &ExportedEvent) -> bool {
    match event.format {
        ExportFormat::V1 => event.mac.is_none() && event.key_id.is_none(),
        ExportFormat::V2 => event.mac.is_some(),
    }
}

/// Check one line against the line before it.
fn check(
    event: &ExportedEvent,
    previous: Option<&ExportedEvent>,
    report: &mut ExportReport,
) -> Option<BreakKind> {
    if event.fields().hash() != event.hash {
        return Some(BreakKind::Edited);
    }
    match previous {
        None => {
            report.first_id = Some(event.id);
            report.from_genesis = event.prev_hash == GENESIS;
        }
        Some(prev) if event.id.0 <= prev.id.0 => return Some(BreakKind::Unlinked),
        Some(prev) if event.id.0 == prev.id.0 + 1 => {
            if event.prev_hash != prev.hash {
                return Some(BreakKind::Unlinked);
            }
        }
        Some(_) => report.gaps += 1,
    }
    None
}

/// Check one line's MAC with `key` (its id, the key) when the key made it.
fn check_mac(
    event: &ExportedEvent,
    key: Option<(&str, &ChainKey)>,
    report: &mut ExportReport,
) -> Option<BreakKind> {
    let ours = key.filter(|(id, _)| event.key_id.as_deref() == Some(*id));
    match (&event.mac, ours) {
        (Some(mac), Some((_, key))) if key.verifies(&event.hash, mac) => report.keyed += 1,
        (Some(_), Some(_)) => return Some(BreakKind::MacMismatch),
        (Some(_), None) => report.keyed_unchecked += 1,
        // Once a line verified with the key, a later line without a MAC had it
        // removed: the key's log keys every event after its first.
        (None, _) if report.keyed > 0 => return Some(BreakKind::MacMissing),
        (None, _) => {}
    }
    None
}

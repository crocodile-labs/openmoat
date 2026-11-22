//! What a person was shown when a call was held for review, beside what ran
//! (OWASP ASI09, human-agent trust exploitation; ADR-110).
//!
//! The guard records a held call with one more reason, [`SHOWN_PREFIX`] and
//! the exact text the host's prompt shows with it. When the host reports
//! afterwards that the call ran (a person approved it), the call's row is
//! found by host, session and call id, and a row is added beside it that says
//! whether the action that ran is the one that was held: a hook, plugin or
//! the agent that changed a call's input after it was shown would otherwise
//! leave no trace. Both rows are chained, keyed and covered by checkpoints.

use openmoat_core::Action;
use rusqlite::{OptionalExtension as _, params};

use super::{EventId, Store, StoreError};

/// The tool name of the row that records what ran after a review.
pub const RAN_AFTER_REVIEW_TOOL: &str = "ran-after-review";

/// What the reason that records a held call's shown text starts with.
pub const SHOWN_PREFIX: &str = "shown: ";

/// The row of a call that was held for review, found when it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldForReview {
    /// The held call's row.
    pub id: EventId,
    /// The text the host's prompt showed, as recorded (redacted).
    pub shown: Option<String>,
    /// Whether the action that ran, recorded as this handle records actions,
    /// is the one the row holds.
    pub same_action: bool,
}

impl Store {
    /// The newest row of call `call_id` of `host`'s session `session_id`, if
    /// it held the call for review, compared with `ran`, the action the host
    /// says ran. `None` for a call whose last row is any other verdict.
    pub fn held_for_review(
        &self,
        host: &str,
        session_id: &str,
        call_id: &str,
        ran: Option<&Action>,
    ) -> Result<Option<HeldForReview>, StoreError> {
        // Found as recorded: every text was redacted with these secrets.
        let secrets = &self.secrets;
        let row: Option<(i64, String, String, String)> = self
            .conn
            .query_row(
                "SELECT id, verdict, action, reasons FROM events
                 WHERE session_id = ?1 AND host = ?2 AND call_id = ?3 AND tool <> ?4
                 ORDER BY id DESC LIMIT 1",
                params![
                    secrets.redact(session_id),
                    secrets.redact(host),
                    secrets.redact(call_id),
                    RAN_AFTER_REVIEW_TOOL
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((id, verdict, action, reasons)) = row else {
            return Ok(None);
        };
        if verdict != openmoat_core::Verdict::Review.as_str() {
            return Ok(None);
        }
        let ran = match ran {
            Some(action) => {
                serde_json::to_string(&secrets.redact_value(serde_json::to_value(action)?))?
            }
            None => "null".to_owned(),
        };
        let shown = serde_json::from_str::<Vec<String>>(&reasons)
            .ok()
            .and_then(|all| {
                all.into_iter()
                    .find_map(|r| r.strip_prefix(SHOWN_PREFIX).map(str::to_owned))
            });
        Ok(Some(HeldForReview {
            id: EventId(id),
            shown,
            same_action: ran == action,
        }))
    }
}

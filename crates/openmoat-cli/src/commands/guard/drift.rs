//! Settings drift the guard decided a call through (`integrity/relaxed.rs`):
//! recorded with the first such call of each session.

use anyhow::{Context as _, Result};
use openmoat_audit::Store;
use openmoat_core::Decision;

use crate::integrity::Drift;

/// Rule id the audit log records settings drift under (`integrity/relaxed.rs`).
const SETTINGS_DRIFT_RULE: &str = "settings-drift";

/// `decision` with `drifted` noted, for the first call of `session` decided
/// through it; `None` when there is no drift or the session already noted it.
pub(super) fn noted(
    store: &Store,
    session: &str,
    decision: &Decision,
    drifted: &[Drift],
) -> Result<Option<Decision>> {
    if drifted.is_empty() || drift_noted(store, session)? {
        return Ok(None);
    }
    Ok(Some(with_drift_note(decision, drifted)))
}

/// Whether an earlier call of `session` already recorded the settings drift.
fn drift_noted(store: &Store, session: &str) -> Result<bool> {
    store
        .session_has_rule(session, SETTINGS_DRIFT_RULE)
        .context("reading this session from the audit log")
}

/// `decision` with the settings drift it was decided through added.
fn with_drift_note(decision: &Decision, drifted: &[Drift]) -> Decision {
    let mut noted = decision.clone();
    noted.rules.push(SETTINGS_DRIFT_RULE.to_owned());
    let drift: Vec<String> = drifted.iter().map(ToString::to_string).collect();
    noted.reasons.push(format!(
        "{}; only settings that change no OpenMoat decision differ, so calls are decided as \
         usual; run `moat doctor` to inspect, `moat doctor --accept` to re-pin",
        drift.join("; ")
    ));
    noted
}

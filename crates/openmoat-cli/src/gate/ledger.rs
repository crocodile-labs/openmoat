//! The policy-change ledger (ADR-117): one audit row of host `openmoat` per
//! widening or re-pin a person's command made, and one per refusal at the gate.
//!
//! The rows are ordinary audit events: hash-chained, keyed with the audit key
//! (ADR-101) and covered by the signed checkpoints (ADR-110), so a row taken
//! out or changed later no longer verifies. A log that cannot take the row is
//! said on stderr; the change itself stands, as `snapshot::record` does. Before
//! `openmoat init` made a log there is nothing to write to.

use openmoat_core::rule_id::{GATE_REFUSED, POLICY_CHANGE};
use openmoat_core::{Decision, Verdict};

use super::Factor;
use crate::home::Home;

/// The session id every ledger row carries, so `openmoat show --session
/// policy-changes` lists them.
pub const SESSION: &str = "policy-changes";

/// Most detail lines one row keeps (the widenings ADR-111 lists): the rest
/// are counted.
const DETAILS: usize = 40;

/// Who ran the command, as far as OpenMoat can tell: the account name the
/// person's shell gives. It is the same account whoever typed; what a
/// person proved is the factor, which the row names separately.
fn who() -> String {
    ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "unknown account".to_owned())
}

/// Record that `command` changed `what`, with `details` (each widening), after
/// the gate let it through with `factor`.
pub fn change(home: &Home, command: &str, factor: Factor, what: &str, details: &[String]) {
    let mut decision = Decision::single(
        Verdict::Allow,
        POLICY_CHANGE,
        format!(
            "{what}; run by {} at a terminal; {}",
            who(),
            factor.describe()
        ),
    );
    decision
        .reasons
        .extend(details.iter().take(DETAILS).cloned());
    if details.len() > DETAILS {
        decision
            .reasons
            .push(format!("… and {} more", details.len() - DETAILS));
    }
    write(home, command, &decision);
}

/// Record that the gate refused `command`, and why.
pub fn refused(home: &Home, command: &str, why: &str) {
    let decision = Decision::single(
        Verdict::Deny,
        GATE_REFUSED,
        format!("{why}; run by {} at a terminal", who()),
    );
    write(home, command, &decision);
}

fn write(home: &Home, command: &str, decision: &Decision) {
    // Before `openmoat init` there is no log to keep a ledger in.
    if !home.audit_path().exists() {
        return;
    }
    let written = crate::audit_key::open_existing(home).and_then(|store| {
        Ok(store.record(&openmoat_audit::NewEvent {
            host: "openmoat",
            session_id: SESSION,
            call_id: None,
            cwd: None,
            tool: command,
            action: None,
            decision,
            latency_us: 0,
        })?)
    });
    if let Err(error) = written {
        eprintln!(
            "openmoat: the audit log did not record `{command}` in the policy-change ledger: {error:#}"
        );
    }
}

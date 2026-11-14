//! Approving a `review` from another device (ADR-078).
//!
//! The guard sends a call it holds for review to a channel only as a signed
//! request file ([`gate::gate_used`]); `openmoat approvals listen`, run by the person,
//! sends it to the approvers and turns an approver's button press into a
//! signed answer ([`Listener`]); the guard uses an approval once, for the
//! exact call it was made for. Every failure leaves the `review` as it was.
//!
//! The core here never names a channel. A channel is a folder under
//! `channels/` with a [`channel::Spec`] and a [`channel::Channel`], listed once in
//! [`channels::REGISTRY`]; only a channel talks to a network (through
//! [`https`]). `tests/architecture.rs` keeps it so.

mod answer;
pub mod channel;
pub mod channels;
mod connect;
mod gate;
mod https;
pub mod listen;
pub mod live;
mod prompt;
mod refused;
mod request;
mod settings;
mod store;
pub mod wait;

#[cfg(test)]
mod tests;

use std::fmt::Write as _;

use anyhow::Result;
use openmoat_audit::NewEvent;
use openmoat_core::Decision;

pub use channel::{Credential, Options, Secrets, Spec};
pub use channels::REGISTRY;
pub use connect::{account, connect, credential_problem, disconnect, open};
#[cfg(test)]
pub use gate::gate;
pub use listen::{Listener, Records, Row};
pub use refused::Approved;
pub use settings::{DEFAULT_EXPIRY_S, MAX_EXPIRY_S, MIN_EXPIRY_S, Settings};
pub use store::Store;

use crate::home::Home;

/// A call's rule when an approval is used for it.
pub const APPROVED_RULE: &str = "approved-remote";
/// The listener's row for an approval given.
pub const APPROVED_ROW_RULE: &str = "remote-approved";
/// An approver's deny: the listener's row, and the call's while it holds.
pub const DENIED_RULE: &str = "remote-denied";
/// An answer or request refused: not an approver, a bad button or signature, too late.
pub const REFUSED_RULE: &str = "remote-refused";
/// A request nobody answered in time.
pub const EXPIRED_RULE: &str = "remote-expired";
/// The tool name of the listener's rows.
pub const ROW_TOOL: &str = "approval";

/// [`gate::gate_used`] in this guard's state directory, now; without a state
/// directory there is no channel, and `decision` stays. With it, the
/// approval the call used, if one was: a call refused after that (its row
/// could not be written) goes to [`Approved::refused`]. `started` is when
/// the guard started and `relayed` whether `openmoat run` started it: with
/// the host's spec they bound how long the gate may wait ([`wait::room`]).
pub fn gated(
    request: &openmoat_hosts::HookRequest,
    decision: Decision,
    known: &openmoat_audit::KnownSecrets,
    (started, relayed): (std::time::Instant, bool),
) -> (Decision, Option<Approved>) {
    let Ok(home) = Home::locate() else {
        return (decision, None);
    };
    let hold = wait::Hold {
        room: wait::room(
            &request.host.spec().hook_failure,
            started.elapsed(),
            relayed,
        ),
        clock: &crate::time::now_ms,
    };
    gate::gate_used(
        &Store::of(&home),
        request,
        decision,
        known,
        (crate::time::now_ms(), &hold),
    )
}

/// `bytes` as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether the hex text `given` spells `expected`, compared in constant time.
fn verify_hex(given: &str, expected: &[u8]) -> bool {
    openmoat_proxy::constant_time_eq(given.as_bytes(), hex(expected).as_bytes())
}

/// The listener's rows, written to the audit log of `home`.
pub struct AuditRecords<'a> {
    pub home: &'a Home,
}

impl Records for AuditRecords<'_> {
    fn record(&mut self, row: Row) -> Result<()> {
        let store = openmoat_audit::Store::open_existing(&self.home.audit_path())?;
        let decision = Decision::single(row.verdict, row.rule, openmoat_audit::redact(&row.reason));
        store.record(&NewEvent {
            host: &row.host,
            session_id: &row.session,
            call_id: None,
            cwd: row.cwd.as_deref(),
            tool: ROW_TOOL,
            action: None,
            decision: &decision,
            latency_us: 0,
        })?;
        Ok(())
    }
}

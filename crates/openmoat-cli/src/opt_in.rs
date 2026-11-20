//! What `openmoat status` and `openmoat doctor` say about the opt-in choices
//! of `openmoat init` (ADR-106): how many decoy keys are planted and whether a
//! call touched one lately, and whether each agent with a sandboxed-start shim
//! starts in `openmoat run` from this shell. Nothing is said about a choice a
//! person did not make.

use openmoat_core::rule_id::CANARY;
use serde::Serialize;

use crate::home::Home;
use crate::start;

/// How far back the decoy row looks for calls that touched one.
const TOUCHED_WINDOW_MS: i64 = 7 * 24 * 3_600_000;

/// One row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OptInRow {
    /// `Decoy keys` or `Sandboxed start`.
    pub label: &'static str,
    pub text: String,
    /// A problem or an alert the person should see first.
    pub attention: bool,
    /// An alert: a call touched a decoy.
    pub alert: bool,
}

impl OptInRow {
    /// The row as `openmoat doctor` writes it: label padded, then the text.
    pub fn doctor_line(&self) -> String {
        format!("{:<16} {}", self.label.to_ascii_lowercase(), self.text)
    }
}

/// The rows for this state directory at `now_ms`, searching for agents with
/// this process's `PATH`.
pub fn rows(home: &Home, now_ms: i64) -> Vec<OptInRow> {
    let mut rows = decoys(home, now_ms);
    let path = crate::environment::absolute_search_path();
    let dir = start::shim_dir(home);
    match start::report(home, &path) {
        Ok(found) => rows.extend(found.into_iter().map(|(shim, starts)| OptInRow {
            label: "Sandboxed start",
            text: format!("{}: {}", shim.name, starts.line(&shim.name, &dir)),
            attention: starts.needs_attention(),
            alert: false,
        })),
        Err(e) => rows.push(OptInRow {
            label: "Sandboxed start",
            text: format!("{e:#}"),
            attention: true,
            alert: false,
        }),
    }
    rows
}

/// The decoy row: how many are planted, and the calls of the last week that
/// touched one, the latest named.
fn decoys(home: &Home, now_ms: i64) -> Vec<OptInRow> {
    let planted = match crate::canary::Record::load(home) {
        Ok(record) => record.decoys.len(),
        Err(e) => {
            return vec![OptInRow {
                label: "Decoy keys",
                text: format!("{e:#}"),
                attention: true,
                alert: false,
            }];
        }
    };
    if planted == 0 {
        return Vec::new();
    }
    let touched = openmoat_audit::Store::open_read_only(&home.audit_path())
        .ok()
        .and_then(|store| store.rule_since(CANARY, now_ms - TOUCHED_WINDOW_MS).ok())
        .flatten();
    let row = match touched {
        None => OptInRow {
            label: "Decoy keys",
            text: format!("{planted} planted; none touched in the last 7 days"),
            attention: false,
            alert: false,
        },
        Some(seen) => OptInRow {
            label: "Decoy keys",
            text: format!(
                "{} call(s) in {} session(s) touched a decoy key in the last 7 days, the latest \
                 at {} from {}: something in that session went looking for keys. `openmoat why \
                 {}` shows the call",
                seen.count,
                seen.sessions,
                crate::time::timestamp(seen.newest.ts_ms),
                seen.newest.host,
                seen.newest.id,
            ),
            attention: true,
            alert: true,
        },
    };
    vec![row]
}

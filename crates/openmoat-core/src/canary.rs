//! Decoy credentials (ADR-106): fake keys `openmoat init` plants at a
//! person's request where an agent hunting for keys looks, and the checks that
//! catch any call reading, changing or sending one.
//!
//! No real work touches a decoy, so a call that does is denied with rule
//! [`CANARY`] whatever else the policy says. Two checks, both only tightening:
//!
//! - the decoys' paths, as a `deny` group put first in the policy
//!   ([`Decoys::guard`]), so every way the engine finds a path (a file tool, a
//!   shell word, a link, an MCP argument) finds a decoy too;
//! - the decoys' values in the text of a call ([`Decoys::checked`],
//!   [`Decoys::checked_text`]): a value read some way the hook did not see
//!   (a process the agent started, a sweep of the home directory) is caught when
//!   it is sent or written.
//!
//! This crate holds no decoy: the CLI reads them from its state and passes
//! them in.

use crate::rule_id::{self, CANARY};
use crate::{Action, Decision, Policy, RuleGroup, Verdict};

/// A value shorter than this is never looked for: it would occur in ordinary
/// text. Every value OpenMoat plants is longer.
pub const MIN_VALUE_LEN: usize = 16;

/// The decoys planted on this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decoys {
    /// Each decoy file, as the policy spells a path (`~/.npmrc.bak`).
    pub paths: Vec<String>,
    /// Each value the decoy files hold, as written there.
    pub values: Vec<String>,
}

impl Decoys {
    /// Whether no decoy is planted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.values.is_empty()
    }

    /// The `deny` group of the decoys' paths: reads and writes, by the hook
    /// only (the OS sandboxes keep their own rules, ADR-034), with the words
    /// of [`CANARY`]. `None` when there is no path.
    #[must_use]
    pub fn rule(&self) -> Option<RuleGroup> {
        if self.paths.is_empty() {
            return None;
        }
        let words = rule_id::words(CANARY);
        Some(RuleGroup {
            id: CANARY.to_owned(),
            reason: Some("a decoy key OpenMoat planted".to_owned()),
            title: words.map(|w| w.title.to_owned()),
            why: words.map(|w| w.why.to_owned()),
            fs_read: self.paths.clone(),
            fs_write: self.paths.clone(),
            hook_only: true,
            ..RuleGroup::default()
        })
    }

    /// `policy` with [`Decoys::rule`] as its first `deny` group, so a call
    /// naming a decoy is decided by it, before any other rule that matches the
    /// same path. Deny is absolute, so this never allows anything.
    pub fn guard(&self, policy: &mut Policy) {
        if let Some(rule) = self.rule() {
            policy.deny.insert(0, rule);
        }
    }

    /// Whether `text` holds one of the decoy values, in any letter case.
    #[must_use]
    pub fn carried(&self, text: &str) -> bool {
        let values: Vec<String> = self.looked_for().map(str::to_ascii_lowercase).collect();
        if values.is_empty() {
            return false;
        }
        let text = text.to_ascii_lowercase();
        values.iter().any(|v| text.contains(v.as_str()))
    }

    /// `decision`, or a deny with rule [`CANARY`] when `action` carries a
    /// decoy value in a command, path, address, query or argument it names.
    #[must_use]
    pub fn checked(&self, action: &Action, decision: Decision) -> Decision {
        if texts(action).iter().any(|t| self.carried(t)) {
            return caught(decision);
        }
        decision
    }

    /// [`Decoys::checked`] over `text`: the whole call as the host sent it,
    /// content written and MCP arguments included.
    #[must_use]
    pub fn checked_text(&self, text: &str, decision: Decision) -> Decision {
        if self.carried(text) {
            return caught(decision);
        }
        decision
    }

    fn looked_for(&self) -> impl Iterator<Item = &str> {
        self.values
            .iter()
            .map(String::as_str)
            .filter(|v| v.len() >= MIN_VALUE_LEN)
    }
}

/// The deny for a call that carries a decoy value; what was decided before is
/// kept as context for the audit log.
fn caught(before: Decision) -> Decision {
    let mut decision = Decision::single(
        Verdict::Deny,
        CANARY,
        "the call carries the value of a decoy key OpenMoat planted; nothing real was \
         exposed, but whatever sent it read a decoy",
    );
    decision.context.extend(before.reasons);
    decision
}

/// Every text `action` names.
fn texts(action: &Action) -> Vec<&str> {
    match action {
        Action::Shell { command } | Action::ForeignShell { command, .. } => vec![command.as_str()],
        Action::FsRead { path } | Action::FsWrite { path } => vec![path.as_str()],
        Action::Net { url } | Action::Fetch { url } => vec![url.as_str()],
        Action::WebSearch { query } => vec![query.as_str()],
        Action::Unchecked { action, .. } => texts(action),
        Action::Patch { writes } => writes.iter().map(String::as_str).collect(),
        Action::ReadFiles { paths } => paths.iter().map(String::as_str).collect(),
        Action::UnknownTool {
            reads,
            writes,
            hosts,
            commands,
            ..
        } => [reads, writes, hosts, commands]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect(),
        Action::McpTool {
            reads,
            writes,
            hosts,
            opens,
            commands,
            value_reads,
            ..
        } => [reads, writes, hosts, opens, commands, value_reads]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect(),
    }
}

#[cfg(test)]
mod tests;

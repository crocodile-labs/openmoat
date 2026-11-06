//! The words of the block message (ADR-059) for one call: the deciding rule's
//! `title` and `why` from the person's policy, and the call and the reasons as
//! they may be shown. `openmoat-hosts` lays them out in each host's reason
//! field ([`openmoat_hosts::reason_line`]); `openmoat watch` and `openmoat
//! why` show calls the same way.

use openmoat_audit::KnownSecrets;
use openmoat_core::{Action, Decision, Notice, Policy, Verdict};

use crate::render::clean;
use crate::report::Paths;

/// The longest call shown, in characters; a longer one loses its middle.
pub const CALL_CHARS: usize = 100;

/// The longest run of reasons shown on the `rule` line.
const DETAIL_CHARS: usize = 300;

/// The title and `why` of each rule of a decision that has one, in the
/// decision's rule order.
#[derive(Debug, Default)]
pub struct Titles(Vec<(String, String, Option<String>)>);

impl Titles {
    /// The titles `policy` gives the rules of `decision`: only from the
    /// person's own rule groups ([`Policy::own_group`]).
    pub fn of(policy: &Policy, decision: &Decision) -> Self {
        Self(
            decision
                .rules
                .iter()
                .filter_map(|id| {
                    let group = policy.own_group(id)?;
                    let title = group.title.clone()?;
                    Some((id.clone(), title, group.why.clone()))
                })
                .collect(),
        )
    }

    /// The title and `why` of `rule`, when it has a title.
    pub fn get(&self, rule: &str) -> Option<(&str, Option<&str>)> {
        self.0
            .iter()
            .find(|(id, _, _)| id == rule)
            .map(|(_, title, why)| (title.as_str(), why.as_deref()))
    }
}

/// The notice for `decision` on a call of `tool` doing `action`: `None` unless
/// it is a `deny` or `review` and one of its rules has a title, so every other
/// decision keeps the one line earlier releases sent. Every text is masked
/// with `known` and the token shapes `openmoat_audit::redact` knows, the home
/// directory shown as `~`, and cleaned of control characters.
pub fn of(
    decision: &Decision,
    titles: &Titles,
    call: Option<(&str, Option<&Action>)>,
    known: &KnownSecrets,
) -> Option<Box<Notice>> {
    if !matches!(decision.verdict, Verdict::Deny | Verdict::Review) {
        return None;
    }
    let (title, why) = decision.rules.iter().find_map(|r| titles.get(r))?;
    let paths = Paths::detect();
    let call = call
        .map(|(tool, action)| middle(&shown(&paths, known, &call_text(tool, action)), CALL_CHARS));
    // The reasons keep their paths as written: the `rule` line is the line
    // earlier releases sent, masked and on one line.
    let reasons = decision.reasons.join("; ");
    Some(Box::new(Notice {
        title: clean(title).into_owned(),
        why: why.map(|w| clean(w).into_owned()),
        call,
        detail: (!reasons.is_empty()).then(|| middle(&masked(known, &reasons), DETAIL_CHARS)),
        unasked: None,
    }))
}

/// `text` as it may be shown: [`masked`], with `~` for the home directory.
pub fn shown(paths: &Paths, known: &KnownSecrets, text: &str) -> String {
    paths.shorten(&masked(known, text))
}

/// `text` with secrets masked, whitespace runs (line breaks included) as one
/// space and control characters as `?`.
fn masked(known: &KnownSecrets, text: &str) -> String {
    let redacted = known.redact(text);
    let one_line = redacted.split_whitespace().collect::<Vec<_>>().join(" ");
    clean(&one_line).into_owned()
}

/// A call as the person would describe it: a command as it is, any other
/// call as its tool and what it names (`Read ~/.ssh/id_ed25519`).
pub fn call_text(tool: &str, action: Option<&Action>) -> String {
    match (action.map(Action::shown), target(action)) {
        (Some(Action::Shell { command }), _) => command.clone(),
        (_, Some(target)) if target != tool => format!("{tool} {target}"),
        _ => tool.to_owned(),
    }
}

/// What a call names: a command, a path, a URL, a query; `None` for a call
/// whose tool name says it all, or an ungoverned tool.
pub fn target(action: Option<&Action>) -> Option<String> {
    Some(match action?.shown() {
        Action::Shell { command } => command.clone(),
        Action::ForeignShell { shell, command } => format!("{shell}: {command}"),
        Action::FsRead { path } | Action::FsWrite { path } => path.clone(),
        Action::Net { url } | Action::Fetch { url } => url.clone(),
        Action::WebSearch { query } => query.clone(),
        Action::Patch { writes } => writes.join(", "),
        Action::ReadFiles { paths } => paths.join(", "),
        Action::McpTool { name, .. } => name.clone(),
        _ => return None,
    })
}

/// `text` cut to `max` characters by taking out its middle, marked `…`, so
/// both the program and what it acts on stay visible.
pub fn middle(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_owned();
    }
    let keep = max.saturating_sub(1);
    let head = keep.div_ceil(2);
    let tail = keep - head;
    let start: String = text.chars().take(head).collect();
    let end: String = text.chars().skip(count - tail).collect();
    format!("{start}…{end}")
}

#[cfg(test)]
mod tests;

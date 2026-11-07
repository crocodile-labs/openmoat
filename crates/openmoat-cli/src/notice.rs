//! The words of the block message (ADR-059) for one call: the deciding rule's
//! `title` and `why` from the person's policy, or those of OpenMoat's own
//! check ([`builtin`]), and the call and the reasons as they may be shown.
//! `openmoat-hosts` lays them out in each host's reason field
//! ([`openmoat_hosts::reason_line`]); `openmoat watch` and `openmoat why` show
//! calls and titles the same way.

use openmoat_audit::KnownSecrets;
use openmoat_core::{Action, Decision, Notice, Policy, Verdict};

use crate::render::clean;
use crate::report::Paths;

mod builtin;

/// The longest call shown, in characters; a longer one loses its middle.
pub const CALL_CHARS: usize = 100;

/// The longest reason shown on the `rule` line; each reason is cut on its own,
/// so a decision of two rules (`runs-later` and `session-taint`) keeps both,
/// the second one's source included.
const DETAIL_CHARS: usize = 300;

/// What heads the message of one rule: its title and `why`, and for one of
/// OpenMoat's own checks the person's step for a decision of that verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Words<'a> {
    pub title: &'a str,
    pub why: Option<&'a str>,
    pub next: Option<(Verdict, &'a str)>,
}

/// The words of `rule`: the person's title for it when it is one of their own
/// rule groups ([`Policy::own_group`]), else those of OpenMoat's own check of
/// that id. A rule of theirs without a title has none: the check's words
/// would describe another rule.
pub fn words<'a>(policy: Option<&'a Policy>, rule: &str) -> Option<Words<'a>> {
    match policy.and_then(|p| p.own_group(rule)) {
        Some(group) => group.title.as_deref().map(|title| Words {
            title,
            why: group.why.as_deref(),
            next: None,
        }),
        None => builtin::words(rule),
    }
}

/// The person's own words for each rule of a decision that is one of their
/// rule groups, in the decision's rule order: `None` for one without a title.
/// Owned, so the guard can drop the compiled policy before it answers.
#[derive(Debug, Default)]
pub struct Titles(Vec<(String, Option<Own>)>);

/// A title and `why` from the person's policy.
#[derive(Debug)]
struct Own {
    title: String,
    why: Option<String>,
}

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
                    let own = group.title.clone().map(|title| Own {
                        title,
                        why: group.why.clone(),
                    });
                    Some((id.clone(), own))
                })
                .collect(),
        )
    }

    /// The words of `rule`, as [`words`] finds them.
    pub fn get(&self, rule: &str) -> Option<Words<'_>> {
        match self.0.iter().find(|(id, _)| id == rule) {
            Some((_, own)) => own.as_ref().map(|own| Words {
                title: &own.title,
                why: own.why.as_deref(),
                next: None,
            }),
            None => builtin::words(rule),
        }
    }
}

/// The notice for `decision` on a call of `tool` doing `action`: `None` unless
/// it is a `deny` or `review` and one of its rules has words ([`words`]), so
/// every other decision keeps the one line earlier releases sent. Every text
/// is masked with `known` and the token shapes `openmoat_audit::redact` knows,
/// the home directory shown as `~`, and cleaned of control characters.
pub fn of(
    decision: &Decision,
    titles: &Titles,
    call: Option<(&str, Option<&Action>)>,
    known: &KnownSecrets,
) -> Option<Box<Notice>> {
    if !matches!(decision.verdict, Verdict::Deny | Verdict::Review) {
        return None;
    }
    let words = decision.rules.iter().find_map(|r| titles.get(r))?;
    let next = words
        .next
        .filter(|(verdict, _)| *verdict == decision.verdict)
        .map(|(_, next)| next.to_owned());
    let paths = Paths::detect();
    let call = call
        .map(|(tool, action)| middle(&shown(&paths, known, &call_text(tool, action)), CALL_CHARS));
    // The reasons keep their paths as written: the `rule` line is the line
    // earlier releases sent, masked and on one line, each reason shortened alone.
    let detail = decision
        .reasons
        .iter()
        .map(|reason| middle(&masked(known, reason), DETAIL_CHARS))
        .collect::<Vec<_>>()
        .join("; ");
    Some(Box::new(Notice {
        title: clean(words.title).into_owned(),
        why: words.why.map(|w| clean(w).into_owned()),
        call,
        detail: (!detail.is_empty()).then_some(detail),
        next,
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

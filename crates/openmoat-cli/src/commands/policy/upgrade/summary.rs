//! What `openmoat policy upgrade` changes, grouped for a person instead of the
//! raw diff: rules that protect more, changes that interrupt less, the
//! `ask` → `review` rename, the count of comment and wording updates and of
//! narrow patterns folded into broader ones, and the directory grants brought
//! up to date (`grants.rs`). Worked out from the policy before and after the
//! merge, read as policies, so a line moved or reworded is never shown as a new
//! rule, nor a pattern its rule still covers as a removal. A change it cannot
//! name is counted under "Other changes", for `d` to show.

use std::collections::BTreeMap;

use openmoat_core::{Kind, Policy, RuleGroup};
use serde_json::Value;

use crate::upgrade::Change;

/// At most this many patterns are named in a line; more are counted.
const NAMED_PATTERNS: usize = 3;
/// A pattern longer than this is counted, not named.
const NAMED_PATTERN_CHARS: usize = 40;

/// The changes, grouped.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Summary {
    /// What is denied or held for review that was not.
    pub protections: Vec<String>,
    /// What is allowed or left to the agent that was not.
    pub fewer: Vec<String>,
    /// The rename of `ask` to `review` (ADR-053).
    pub renamed: bool,
    /// Changes of comments, blank lines and rule reasons only.
    pub wording: usize,
    /// Patterns taken out of a group that a broader pattern of the same group
    /// still matches as a whole, so nothing is decided differently.
    pub folded: usize,
    /// Directory grants `openmoat policy upgrade` brings up to date
    /// ([`crate::approvals::DirGrant`]), one line each.
    pub dir_grants: Vec<String>,
    /// Other changes, named: a section of the policy that changed.
    pub other: Vec<String>,
    /// Changes of the text that none of the above explains.
    pub unexplained: usize,
}

/// The list a rule group is in, and how its matches are decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum List {
    Deny,
    Review,
    Allow,
    Defer,
}

impl List {
    /// Whether a match in this list lets the call through without the person.
    fn lets_through(self) -> bool {
        matches!(self, Self::Allow | Self::Defer)
    }

    fn name(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Review => "review",
            Self::Allow => "allow",
            Self::Defer => "defer",
        }
    }
}

/// The grouped summary of going from `current` to `merged` with `changes`
/// (the merge's applied stretches) and, when `renamed`, the rename.
pub(super) fn summarise(
    current: &str,
    merged: &str,
    changes: &[&Change],
    renamed: bool,
) -> Summary {
    let mut summary = Summary {
        renamed,
        ..Summary::default()
    };
    let wording_only = changes
        .iter()
        .filter(|c| without_comments(&c.yours) == without_comments(&c.default))
        .count();
    let code = changes.len() - wording_only;
    summary.wording = wording_only;
    match (Policy::parse(current), Policy::parse(merged)) {
        (Ok(before), Ok(after)) => {
            summary.wording += rules(&before, &after, &mut summary);
            sections(&before, &after, &mut summary);
            let named = summary.protections.len()
                + summary.fewer.len()
                + summary.other.len()
                + summary.folded;
            if named == 0 && summary.wording == wording_only {
                summary.unexplained = code;
            }
        }
        // Not read as policies: nothing is named that cannot be shown to be so.
        _ => summary.unexplained = code,
    }
    summary
}

impl Summary {
    /// The groups, each line under its heading, two spaces in.
    pub fn write(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        let groups = [
            ("New protections", "+", &self.protections),
            ("Fewer interruptions", "−", &self.fewer),
            ("Other changes", "·", &self.other),
            ("Directory grants", "+", &self.dir_grants),
        ];
        for (heading, mark, lines) in groups {
            if lines.is_empty() {
                continue;
            }
            writeln!(out, "  {heading}")?;
            for line in lines {
                writeln!(out, "    {mark} {}", crate::render::clean(line))?;
            }
        }
        if self.renamed {
            writeln!(out, "  Renamed")?;
            writeln!(out, "    ~ `ask` is now `review` (same behaviour)")?;
        }
        if self.wording > 0 {
            let updates = crate::report::count(self.wording, "comment and wording update");
            writeln!(out, "  + {updates}")?;
        }
        if self.folded > 0 {
            let narrow = crate::report::count(self.folded, "narrow pattern");
            writeln!(out, "  + {narrow} now matched by a broader one")?;
        }
        if self.unexplained > 0 {
            writeln!(out, "  Other changes: {} (d to see)", self.unexplained)?;
        }
        Ok(())
    }
}

/// Every rule group by id, with its list.
fn groups(policy: &Policy) -> BTreeMap<&str, (List, &RuleGroup)> {
    let lists = [
        (List::Deny, &policy.deny),
        (List::Review, &policy.review),
        (List::Allow, &policy.allow),
        (List::Defer, &policy.defer),
    ];
    lists
        .into_iter()
        .flat_map(|(list, groups)| groups.iter().map(move |g| (g.id.as_str(), (list, g))))
        .collect()
}

/// The rule changes, each in its group; returns how many changed their
/// reason only.
fn rules(before: &Policy, after: &Policy, summary: &mut Summary) -> usize {
    let (old, new) = (groups(before), groups(after));
    let mut reworded = 0;
    for (id, (list, group)) in &new {
        match old.get(id) {
            None => added_group(*list, group, summary),
            Some((was, _)) if was != list => summary.other.push(format!(
                "`{id}` moved from `{}:` to `{}:`",
                was.name(),
                list.name()
            )),
            Some((_, was)) => {
                let patterns = pattern_changes(*list, id, was, group, summary);
                // A reason, title or why (ADR-059) changes the words shown, not what is decided.
                let rest_same = RuleGroup {
                    reason: group.reason.clone(),
                    title: group.title.clone(),
                    why: group.why.clone(),
                    ..(*was).clone()
                } == **group;
                let words = (&was.reason, &was.title, &was.why)
                    != (&group.reason, &group.title, &group.why);
                if !patterns && words && rest_same {
                    reworded += 1;
                } else if was.hook_only != group.hook_only {
                    summary.other.push(format!("`{id}`: `hook_only` changed"));
                }
            }
        }
    }
    for (id, (list, _)) in old.iter().filter(|(id, _)| !new.contains_key(*id)) {
        let line = format!("`{id}` removed (it was a `{}:` rule)", list.name());
        if list.lets_through() {
            summary.protections.push(line);
        } else {
            summary.fewer.push(line);
        }
    }
    reworded
}

/// A rule group the policy did not have.
fn added_group(list: List, group: &RuleGroup, summary: &mut Summary) {
    let what = group
        .title
        .clone()
        .or_else(|| group.reason.clone())
        .unwrap_or_else(|| patterns_phrase(&all_patterns(group)));
    let id = &group.id;
    match list {
        List::Deny => summary.protections.push(format!("Denied: {what} (`{id}`)")),
        List::Review => summary
            .protections
            .push(format!("Needs your review: {what} (`{id}`)")),
        List::Allow => summary.fewer.push(format!("Allowed: {what} (`{id}`)")),
        List::Defer => summary
            .fewer
            .push(format!("Left to the agent: {what} (`{id}`)")),
    }
}

/// The patterns `group` gained and lost, one line per direction; whether
/// there were any. A pattern starting with `!` is an exception to the group,
/// so adding one does the opposite of adding a plain pattern. A pattern lost
/// that one the group keeps or gains still matches as a whole is counted in
/// [`Summary::folded`], not named: the group decides it as before.
fn pattern_changes(
    list: List,
    id: &str,
    was: &RuleGroup,
    now: &RuleGroup,
    summary: &mut Summary,
) -> bool {
    let folded_before = summary.folded;
    let (mut tighter, mut wider) = (Vec::new(), Vec::new());
    for kind in Kind::ALL {
        let (old, new) = (was.patterns(kind), now.patterns(kind));
        let added = new.iter().filter(|p| !old.contains(p)).map(|p| (p, true));
        let removed = old.iter().filter(|p| !new.contains(p));
        let (folded, removed): (Vec<&String>, Vec<&String>) =
            removed.partition(|p| still_covered(kind, p, new));
        summary.folded += folded.len();
        for (pattern, added) in added.chain(removed.into_iter().map(|p| (p, false))) {
            let shown = pattern.strip_prefix('!');
            // A plain pattern added to a deny or review group protects more;
            // an exception, a removal or an allow group each turn that round.
            let side = if added ^ shown.is_some() ^ list.lets_through() {
                &mut tighter
            } else {
                &mut wider
            };
            side.push(shown.unwrap_or(pattern.as_str()));
        }
    }
    let (now_covers, no_longer) = match list {
        List::Deny => ("now also denies", "no longer denies"),
        List::Review => ("now also holds for review", "no longer holds for review"),
        List::Allow => ("no longer allows", "now also allows"),
        List::Defer => (
            "no longer leaves to the agent",
            "now also leaves to the agent",
        ),
    };
    if !tighter.is_empty() {
        let line = format!("`{id}` {now_covers} {}", patterns_phrase(&tighter));
        summary.protections.push(line);
    }
    if !wider.is_empty() {
        let line = format!("`{id}` {no_longer} {}", patterns_phrase(&wider));
        summary.fewer.push(line);
    }
    !(tighter.is_empty() && wider.is_empty()) || summary.folded > folded_before
}

/// Whether `removed`, a pattern a group of `kind` no longer lists, is still
/// matched as a whole by one of the group's `patterns`: a plain pattern by a
/// plain one, an exclusion by an exclusion (`**/.vscode/**` for
/// `**/.vscode/tasks.json`). Then taking it out decides nothing differently.
/// Conservative: when the core cannot show it ([`openmoat_core::lint::covers`]),
/// the removal is reported as one.
fn still_covered(kind: Kind, removed: &str, patterns: &[String]) -> bool {
    let (negated, body) = split_exclusion(removed);
    patterns.iter().any(|p| {
        let (by_negated, by) = split_exclusion(p);
        by_negated == negated && openmoat_core::lint::covers(kind, by, body)
    })
}

/// `!pattern` → `(true, "pattern")`.
fn split_exclusion(pattern: &str) -> (bool, &str) {
    pattern
        .strip_prefix('!')
        .map_or((false, pattern), |body| (true, body))
}

fn all_patterns(group: &RuleGroup) -> Vec<&str> {
    Kind::ALL
        .iter()
        .flat_map(|k| group.patterns(*k))
        .map(String::as_str)
        .collect()
}

/// A few short patterns by name, else how many: `` `git config user.name` ``,
/// `5 patterns`.
fn patterns_phrase(patterns: &[&str]) -> String {
    let short = patterns.len() <= NAMED_PATTERNS
        && patterns
            .iter()
            .all(|p| p.chars().count() <= NAMED_PATTERN_CHARS);
    if short && !patterns.is_empty() {
        let named: Vec<String> = patterns.iter().map(|p| format!("`{p}`")).collect();
        named.join(", ")
    } else {
        crate::report::count(patterns.len(), "pattern")
    }
}

/// Every top-level section besides the rule lists that differs: `defaults`,
/// `sandbox`, `executables`, …
fn sections(before: &Policy, after: &Policy, summary: &mut Summary) {
    let rest = |policy: &Policy| -> Option<serde_json::Map<String, Value>> {
        let Value::Object(mut map) = serde_json::to_value(policy).ok()? else {
            return None;
        };
        for list in ["deny", "review", "allow", "defer"] {
            map.remove(list);
        }
        Some(map)
    };
    let (Some(old), Some(new)) = (rest(before), rest(after)) else {
        return;
    };
    let keys: std::collections::BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    for key in keys {
        if old.get(key) != new.get(key) {
            summary.other.push(format!("`{key}:` changed"));
        }
    }
}

/// `text` without comment lines, blank lines, trailing comments and trailing
/// spaces: what YAML reads of it.
fn without_comments(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| strip_comment(line).trim_end().to_owned())
        .filter(|line| !line.trim().is_empty())
        .collect()
}

/// `line` up to a `#` that starts a comment: at the start, or after a space
/// outside quotes.
fn strip_comment(line: &str) -> &str {
    let (mut single, mut double) = (false, false);
    let mut previous = ' ';
    for (at, c) in line.char_indices() {
        match c {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double && previous.is_whitespace() => return &line[..at],
            _ => {}
        }
        previous = c;
    }
    line
}

#[cfg(test)]
mod tests;

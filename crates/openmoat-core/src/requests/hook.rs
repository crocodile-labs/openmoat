//! The hook's half of request rules (ADR-062): a shell command or fetch tool
//! that sends a request to a `requests:` host is decided with the same rules
//! the proxy holds, from what its words show (`command.rs`).
//!
//! - Known method and target, refused for every method it may be sent with:
//!   `deny` (`request-rule`).
//! - Refused for some of them, or known only in part (a method or URL made at
//!   run time) where a rule could refuse it: `review` (`request-rule`).
//! - Otherwise nothing: these decisions only narrow, never allow.

use super::command::{self, Seen, Target};
use super::{RequestCheck, RequestRules};
use crate::action::{Action, AtomicAction};
use crate::rule_id::REQUEST_RULE;
use crate::verdict::{Decision, Verdict};

/// The decisions the request rules add to `action`, whose atoms the
/// classifier found (`atoms`); empty without `requests:` entries.
pub(crate) fn decisions(
    rules: &RequestRules,
    action: &Action,
    atoms: &[AtomicAction],
) -> Vec<Decision> {
    if rules.is_empty() {
        return Vec::new();
    }
    let fetched = match action.shown() {
        Action::Fetch { url } => command::fetch(url),
        _ => None,
    };
    let commands = atoms.iter().filter_map(|atom| match atom {
        AtomicAction::Shell { argv } => Some(command::read(argv)),
        _ => None,
    });
    fetched
        .into_iter()
        .chain(commands.flatten())
        .filter_map(|seen| decide(rules, &seen))
        .collect()
}

fn decide(rules: &RequestRules, seen: &Seen) -> Option<Decision> {
    if seen.host.as_deref().is_some_and(|h| !rules.names(h)) {
        return None;
    }
    let to = seen
        .host
        .as_deref()
        .unwrap_or("a host its words do not name");
    let headers: Vec<&str> = seen.headers.iter().map(String::as_str).collect();
    if let (Some(host), Some(methods), Target::Known(target)) =
        (&seen.host, &seen.methods, &seen.target)
    {
        let refused: Vec<String> = methods
            .iter()
            .filter_map(|m| match rules.check(host, m, target, &headers) {
                RequestCheck::Refused(why) => Some(why),
                _ => None,
            })
            .collect();
        let first = refused.first()?;
        let verdict = if refused.len() == methods.len() {
            Verdict::Deny
        } else {
            Verdict::Review
        };
        let why = if verdict == Verdict::Deny {
            format!("{}: {first}", seen.program)
        } else {
            format!(
                "{}: the request may be sent as {} (standard input may hold a body), and {first}",
                seen.program,
                methods.join(" or ")
            )
        };
        return Some(Decision::single(verdict, REQUEST_RULE, why));
    }
    // A header that asks for another method is refused whatever the rest is.
    if let Some(host) = &seen.host
        && let Some(name) = headers.iter().find(|name| {
            crate::route::METHOD_OVERRIDE_HEADERS
                .iter()
                .any(|h| name.eq_ignore_ascii_case(h))
        })
    {
        return Some(Decision::single(
            Verdict::Deny,
            REQUEST_RULE,
            format!(
                "{}: the request to {host} is refused: its `{name}` header asks the server for \
                 another method",
                seen.program
            ),
        ));
    }
    let path = match &seen.target {
        Target::Known(target) => crate::route::RequestPath::parse(target).ok().map(|p| {
            p.segments()
                .iter()
                .cloned()
                .map(crate::route::Partial::Known)
                .collect()
        }),
        Target::Partial(parts) => Some(parts.clone()),
        Target::Unknown => None,
    };
    let methods: Vec<Option<&str>> = match &seen.methods {
        Some(list) => list.iter().map(|m| Some(m.as_str())).collect(),
        None => vec![None],
    };
    let why = methods
        .iter()
        .find_map(|m| rules.could_refuse(seen.host.as_deref(), *m, path.as_deref()))?;
    Some(Decision::single(
        Verdict::Review,
        REQUEST_RULE,
        format!(
            "{}: the request to {to} is made in part at run time (its method, host or path), so \
             OpenMoat cannot read it in full, and {why}",
            seen.program
        ),
    ))
}

#[cfg(test)]
mod tests;

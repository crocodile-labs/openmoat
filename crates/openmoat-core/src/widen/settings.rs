//! What changed between two policies outside what a call's verdict shows:
//! the rule lists by id (informational, `RuleChange`), and every setting,
//! each with the direction it moves protection (`Change`, ADR-111).
//!
//! A setting whose direction this code cannot tell (a changed `staging:`
//! section, a changed brokered secret) is `Unchecked`: a person looks at it,
//! as at a widening. `taint:` is ranked key by key.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::kind::Kind;
use crate::policy::{Policy, RuleGroup};
use crate::taint::TaintSettings;
use crate::verdict::Verdict;

/// How one setting change moves protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// Less is held: the change widens.
    Widens,
    /// More is held.
    Narrows,
    /// Changed in a way this check does not rank: a person looks.
    Unchecked,
}

/// One setting that changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// The setting (`sandbox.read_roots`, `defaults.net`, `executables.git`).
    pub setting: String,
    /// What changed, in a line.
    pub what: String,
    /// How it moves protection.
    pub effect: Effect,
}

/// One rule group or `requests:` entry that was added, removed, moved to
/// another list or given other patterns. Informational: the verdicts decide
/// whether it widens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleChange {
    /// The list it is in (or was in, when removed).
    pub list: &'static str,
    /// The group's id, or `requests.<id>` for a request entry.
    pub id: String,
    /// `added`, `removed`, `moved from <list>` or `changed`.
    pub change: String,
}

fn lists(policy: &Policy) -> [(&'static str, &[RuleGroup]); 5] {
    [
        ("deny", &policy.deny),
        ("repository review", &policy.repo_review),
        ("allow", &policy.allow),
        ("review", &policy.review),
        ("defer", &policy.defer),
    ]
}

/// The rule groups and request entries added, removed, moved or changed.
pub(super) fn rule_changes(old: &Policy, new: &Policy) -> Vec<RuleChange> {
    // Each id with its list and what it matches, written out to compare.
    let index = |p: &Policy| -> BTreeMap<String, (&'static str, String)> {
        let mut map: BTreeMap<_, _> = lists(p)
            .into_iter()
            .flat_map(|(list, groups)| {
                groups
                    .iter()
                    .map(move |g| (g.id.clone(), (list, fingerprint(g))))
            })
            .collect();
        for entry in &p.requests {
            map.insert(
                format!("requests.{}", entry.id),
                ("requests", format!("{entry:?}")),
            );
        }
        map
    };
    let (before, after) = (index(old), index(new));
    let mut out = Vec::new();
    for (id, (list, group)) in &before {
        let change = match after.get(id) {
            None => "removed".to_owned(),
            Some((now, _)) if now != list => format!("moved from {list}"),
            Some((_, now)) if now != group => "changed".to_owned(),
            Some(_) => continue,
        };
        let list = after.get(id).map_or(*list, |(now, _)| *now);
        out.push(RuleChange {
            list,
            id: id.clone(),
            change,
        });
    }
    for (id, (list, _)) in &after {
        if !before.contains_key(id) {
            out.push(RuleChange {
                list,
                id: id.clone(),
                change: "added".to_owned(),
            });
        }
    }
    out
}

/// What a group matches, as text: its patterns per kind, `hook_only` and its
/// `when` conditions (ADR-113).
fn fingerprint(group: &RuleGroup) -> String {
    let patterns: Vec<&[String]> = Kind::ALL.iter().map(|k| group.patterns(*k)).collect();
    format!("{patterns:?} {} {:?}", group.hook_only, group.when)
}

/// Every setting that differs, with its effect.
pub(super) fn changes(old: &Policy, new: &Policy) -> Vec<Change> {
    let mut out = Vec::new();
    let mut push = |setting: &str, what: String, effect: Effect| {
        out.push(Change {
            setting: setting.to_owned(),
            what,
            effect,
        });
    };
    for kind in Kind::ALL {
        let (was, now) = (old.defaults.for_kind(kind).0, new.defaults.for_kind(kind).0);
        if was != now {
            push(&format!("defaults.{kind}"), moved(was, now), rank(was, now));
        }
    }
    let (was, now) = (old.defaults.unclassified(), new.defaults.unclassified());
    if was != now {
        push(
            "defaults.\"*\" (unparseable calls)",
            moved(was, now),
            rank(was, now),
        );
    }
    executables(old, new, &mut push);
    flags(old, new, &mut push);
    sandbox(old, new, &mut push);
    taint(old, new, &mut push);
    for (setting, same) in [
        ("staging", old.staging == new.staging),
        ("check_diff", old.check_diff == new.check_diff),
        (
            "require",
            old.require == new.require && old.require_added == new.require_added,
        ),
    ] {
        if !same {
            push(setting, "changed".to_owned(), Effect::Unchecked);
        }
    }
    let secrets = |p: &Policy| -> BTreeMap<String, String> {
        p.secrets
            .iter()
            .map(|s| (s.id.clone(), format!("{}{}", s.host, s.header)))
            .collect()
    };
    let (was, now) = (secrets(old), secrets(new));
    for id in was.keys().chain(now.keys()).collect::<BTreeSet<_>>() {
        let (a, b) = (
            old.secrets.iter().find(|s| &s.id == id),
            new.secrets.iter().find(|s| &s.id == id),
        );
        match (a, b) {
            (Some(_), None) => push(
                &format!("secrets.{id}"),
                "removed: no longer kept from the agent".to_owned(),
                Effect::Widens,
            ),
            (None, Some(_)) => push(
                &format!("secrets.{id}"),
                "added".to_owned(),
                Effect::Narrows,
            ),
            (Some(a), Some(b)) if a != b => push(
                &format!("secrets.{id}"),
                "changed".to_owned(),
                Effect::Unchecked,
            ),
            _ => {}
        }
    }
    out
}

fn moved(was: Verdict, now: Verdict) -> String {
    format!("{} → {}", was.as_str(), now.as_str())
}

fn rank(was: Verdict, now: Verdict) -> Effect {
    if now < was {
        Effect::Widens
    } else {
        Effect::Narrows
    }
}

/// A switch that widens one way: `widening` says whether the new value is the
/// wider one.
fn switch<T: std::fmt::Debug + PartialEq + Copy>(
    setting: &str,
    was: T,
    now: T,
    widening: bool,
    push: &mut impl FnMut(&str, String, Effect),
) {
    if was != now {
        let effect = if widening {
            Effect::Widens
        } else {
            Effect::Narrows
        };
        push(setting, format!("{was:?} → {now:?}"), effect);
    }
}

/// A list whose every entry holds more (a path that is private or protected,
/// a server whose results taint): an entry gone widens, entries only added
/// narrow. A glob replaced by a wider one counts as gone.
fn holding_list(
    setting: &str,
    was: &[String],
    now: &[String],
    push: &mut impl FnMut(&str, String, Effect),
) {
    let gone: Vec<&String> = was.iter().filter(|p| !now.contains(p)).collect();
    if !gone.is_empty() {
        push(setting, format!("no longer lists {gone:?}"), Effect::Widens);
    } else if now.iter().any(|p| !was.contains(p)) {
        push(setting, "lists more".to_owned(), Effect::Narrows);
    }
}

/// The `taint:` section, key by key (ADR-113 ranks the lethal trifecta's).
fn taint(old: &Policy, new: &Policy, push: &mut impl FnMut(&str, String, Effect)) {
    let empty = TaintSettings::default();
    let a = old.taint.as_ref().unwrap_or(&empty);
    // Every key named, so a key added to the section must be ranked here.
    let TaintSettings {
        protected_writes,
        metadata_tools,
        defined_servers,
        provenance: _,
        private_paths,
        trifecta: _,
    } = new.taint.as_ref().unwrap_or(&empty);
    let (old_taint, new_taint) = (old.taint.as_ref(), new.taint.as_ref());
    holding_list(
        "taint.protected_writes",
        &a.protected_writes,
        protected_writes,
        push,
    );
    holding_list(
        "taint.defined_servers",
        &a.defined_servers,
        defined_servers,
        push,
    );
    holding_list("taint.private_paths", &a.private_paths, private_paths, push);
    // A metadata tool's results do not taint: one added holds less.
    let trusted: Vec<&String> = metadata_tools
        .iter()
        .filter(|t| !a.metadata_tools.contains(t))
        .collect();
    if !trusted.is_empty() {
        push(
            "taint.metadata_tools",
            format!("results of {trusted:?} no longer taint"),
            Effect::Widens,
        );
    } else if a.metadata_tools.iter().any(|t| !metadata_tools.contains(t)) {
        push(
            "taint.metadata_tools",
            "fewer tools".to_owned(),
            Effect::Narrows,
        );
    }
    let (x, y) = (
        TaintSettings::provenance_on(old_taint),
        TaintSettings::provenance_on(new_taint),
    );
    switch("taint.provenance", x, y, x && !y, push);
    let (was, now) = (
        TaintSettings::trifecta_under(old_taint),
        TaintSettings::trifecta_under(new_taint),
    );
    if was != now {
        push("taint.trifecta", moved(was, now), rank(was, now));
    }
}

fn executables(old: &Policy, new: &Policy, push: &mut impl FnMut(&str, String, Effect)) {
    let names: BTreeSet<&String> = old
        .executables
        .keys()
        .chain(new.executables.keys())
        .collect();
    for name in names {
        let setting = format!("executables.{name}");
        match (old.executables.get(name), new.executables.get(name)) {
            (Some(_), None) => push(
                &setting,
                "pin removed: any path runs".to_owned(),
                Effect::Widens,
            ),
            (None, Some(_)) => push(&setting, "pin added".to_owned(), Effect::Narrows),
            (Some(a), Some(b)) => {
                let added: Vec<&String> = b.iter().filter(|p| !a.contains(p)).collect();
                if !added.is_empty() {
                    push(
                        &setting,
                        format!("may also run from {added:?}"),
                        Effect::Widens,
                    );
                } else if a != b {
                    push(&setting, "fewer paths".to_owned(), Effect::Narrows);
                }
            }
            (None, None) => {}
        }
    }
}

fn flags(old: &Policy, new: &Policy, push: &mut impl FnMut(&str, String, Effect)) {
    let (a, b) = (
        old.require_signed_repo_policy,
        new.require_signed_repo_policy,
    );
    switch("require_signed_repo_policy", a, b, a && !b, push);
    let (a, b) = (old.requests_untrusted(), new.requests_untrusted());
    switch(
        "requests_untrusted",
        a,
        b,
        b == crate::requests::Untrusted::Relay,
        push,
    );
    let (a, b) = (old.unattended(), new.unattended());
    // The setting has the name of the rule it decides by.
    switch(
        crate::rule_id::UNATTENDED,
        a,
        b,
        b == crate::policy::Unattended::Defer,
        push,
    );
    // `hold` holds every new or changed foreign hook's calls; `warn` only
    // those whose command the policy denies (ADR-109).
    let (a, b) = (old.foreign_hooks(), new.foreign_hooks());
    switch(
        "hooks.foreign",
        a,
        b,
        b == crate::policy::ForeignHooks::Warn,
        push,
    );
    let (a, b) = (old.trust_mcp_first_sight(), new.trust_mcp_first_sight());
    switch("mcp.trust_first_sight", a, b, b, push);
    let (a, b) = (old.browser_open_is_fetch(), new.browser_open_is_fetch());
    switch("mcp.browser_open (as fetch)", a, b, b, push);
    let added: Vec<&String> = new
        .mcp_flow_trusted()
        .iter()
        .filter(|s| !old.mcp_flow_trusted().contains(s))
        .collect();
    if !added.is_empty() {
        push(
            "mcp.flow_trusted",
            format!("now trusts {added:?}"),
            Effect::Widens,
        );
    } else if old.mcp_flow_trusted() != new.mcp_flow_trusted() {
        push(
            "mcp.flow_trusted",
            "trusts fewer servers".to_owned(),
            Effect::Narrows,
        );
    }
}

fn sandbox(old: &Policy, new: &Policy, push: &mut impl FnMut(&str, String, Effect)) {
    let empty = crate::policy::SandboxSettings::default();
    let (a, b) = (
        old.sandbox.as_ref().unwrap_or(&empty),
        new.sandbox.as_ref().unwrap_or(&empty),
    );
    let added: Vec<&String> = b
        .read_roots
        .iter()
        .filter(|r| !a.read_roots.contains(r))
        .collect();
    if !added.is_empty() {
        push(
            "sandbox.read_roots",
            format!("commands may also read {added:?}"),
            Effect::Widens,
        );
    } else if a.read_roots != b.read_roots {
        push(
            "sandbox.read_roots",
            "fewer read roots".to_owned(),
            Effect::Narrows,
        );
    }
    let added: Vec<&String> = b
        .env_allow
        .iter()
        .filter(|r| !a.env_allow.contains(r))
        .collect();
    if !added.is_empty() {
        push(
            "sandbox.env_allow",
            format!("also passes {added:?}"),
            Effect::Widens,
        );
    } else if a.env_allow != b.env_allow {
        push(
            "sandbox.env_allow",
            "passes fewer variables".to_owned(),
            Effect::Narrows,
        );
    }
    switch(
        "sandbox.proxy_allow_ech",
        a.proxy_allow_ech,
        b.proxy_allow_ech,
        b.proxy_allow_ech,
        push,
    );
    let (x, y) = (
        a.proxy_serve_without_credential,
        b.proxy_serve_without_credential,
    );
    switch("sandbox.proxy_serve_without_credential", x, y, y, push);
    let (x, y) = (
        old.package_min_release_age_days(),
        new.package_min_release_age_days(),
    );
    switch("sandbox.package_min_release_age_days", x, y, y < x, push);
    let (x, y) = (
        old.run_env().unwrap_or(crate::RunEnv::DEFAULT),
        new.run_env().unwrap_or(crate::RunEnv::DEFAULT),
    );
    switch("sandbox.env", x, y, y == crate::RunEnv::Inherited, push);
    let (x, y) = (old.project_top(), new.project_top());
    switch(
        "sandbox.project_top",
        x,
        y,
        y == crate::ProjectTop::Writable,
        push,
    );
    // Strict refuses a run without every kernel feature (ADR-108): turning
    // it off lets a weaker boundary run.
    let (x, y) = (old.sandbox_strict(), new.sandbox_strict());
    switch("sandbox.strict", x, y, x && !y, push);
    let (x, y) = (old.project_hook_off(), new.project_hook_off());
    switch(
        "sandbox.project_hook_off",
        x,
        y,
        y == crate::ProjectHookOff::Start,
        push,
    );
}

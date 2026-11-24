//! The foreign-hook ledger (ADR-109): every hook command, plugin hook and
//! program-running setting an agent loads besides OpenMoat's own hook, and
//! every program a repository's git configuration names, pinned in the policy
//! lock by digest.
//!
//! A plugin update or a settings edit that adds a hook makes the agent run
//! that hook's command with the person's permissions, at events OpenMoat may
//! never see; git runs what `.git/config` names before any hook. OpenMoat
//! cannot stop those programs, but it does not go on as if nothing changed:
//! while one is new or differs from its pin, `openmoat status`, `openmoat
//! doctor` and `openmoat watch` name it with the shell classifier's verdict
//! on its command, until a person accepts it (`openmoat hooks accept`, from
//! a terminal). Only one whose command the classifier denies changes the
//! agent's calls: `openmoat guard` denies every call of the agent that loads
//! it. The person's policy can hold the calls for every one instead
//! (`hooks.foreign: hold`): review, or deny where the command is denied.
//!
//! A lock from before the ledger (`hook_ledger: None`) holds nothing: the
//! first `openmoat init`, `openmoat hooks accept` or `openmoat doctor
//! --accept` records what is there, and `status` and `doctor` say until then
//! that it is not recorded. Pins of files the scan did not read (another
//! project's) stay as they are.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_core::rule_id::FOREIGN_HOOK;
use openmoat_core::{Action, CompiledPolicy, Decision, ForeignHooks, Verdict};
use openmoat_hosts::Host;
use serde::{Deserialize, Serialize};

use crate::home::Home;
use crate::integrity::Lock;

mod sources;

/// How many characters of a command a pin keeps to show.
const SHOWN_CHARS: usize = 300;

/// One thing the scan found that runs a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// `<file>#<event>@<digest>` for a hook entry, `<file>#<key>` for a
    /// setting, `<file>` for a file pinned by its bytes.
    pub id: String,
    /// The agent that loads it; `None` for git, which every agent runs.
    pub host: Option<Host>,
    pub file: PathBuf,
    /// What it is, in a few words: `plugin hook` and the event.
    pub what: String,
    /// The command lines it runs; empty for a file of code.
    pub commands: Vec<String>,
    /// SHA-256 of what is pinned: the entry in canonical JSON, the value, or
    /// the file's bytes.
    pub digest: String,
}

/// What a scan read.
#[derive(Debug, Default)]
pub struct Scan {
    pub found: Vec<Found>,
    /// The files read (their display paths): a pin of one of them that the
    /// scan did not find again was removed.
    pub scanned: BTreeSet<String>,
}

/// One pinned entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookPin {
    /// The agent's id; empty for git.
    pub host: String,
    pub file: String,
    pub what: String,
    pub digest: String,
    /// The commands as a person was shown them, token-shaped text redacted.
    pub shown: String,
}

/// Entry id → pin.
pub type Pins = BTreeMap<String, HookPin>;

impl HookPin {
    fn of(found: &Found) -> Self {
        Self {
            host: found.host.map(|h| h.id().to_owned()).unwrap_or_default(),
            file: found.file.display().to_string(),
            what: found.what.clone(),
            digest: found.digest.clone(),
            shown: shown(&found.commands),
        }
    }
}

/// The commands as one line a person reads: redacted, cut to a line's length.
fn shown(commands: &[String]) -> String {
    if commands.is_empty() {
        return "(a file of code; OpenMoat cannot read what it runs)".to_owned();
    }
    let text = openmoat_audit::redact(&commands.join("; "));
    let cut: String = text.chars().take(SHOWN_CHARS).collect();
    if cut.len() < text.len() {
        format!("{cut}…")
    } else {
        cut
    }
}

/// A new or changed entry, with the classifier's verdict on what it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub found: Found,
    /// Whether a pin of the same id existed (with another digest).
    pub changed: bool,
    /// The strictest verdict the shell classifier gives its commands under
    /// the person's policy; `review` for a file of code.
    pub verdict: Verdict,
    /// The rules behind that verdict.
    pub rules: Vec<String>,
}

impl Change {
    /// Whether it changes the calls of the agent that loads it under
    /// `mode`: one whose command is denied always does; any does under
    /// `hooks.foreign: hold`.
    pub fn holds(&self, mode: ForeignHooks) -> bool {
        self.verdict == Verdict::Deny || mode == ForeignHooks::Hold
    }

    /// What it does to the agent's calls until a person accepts it, for the
    /// fix line under `mode`.
    pub fn effect(&self, mode: ForeignHooks) -> &'static str {
        if self.verdict == Verdict::Deny {
            "until then the agent's calls are denied"
        } else if mode == ForeignHooks::Hold {
            "until then the agent's calls are held for review"
        } else {
            "the agent's calls are not held (`hooks.foreign: hold` in your policy holds them)"
        }
    }

    /// One line naming it and its verdict, then what it runs. All of it comes
    /// from the agent's files, so every line goes through
    /// [`crate::render::clean`].
    pub fn describe(&self) -> String {
        // A git program's `what` already starts with `git config`.
        let subject = self.found.host.map_or_else(
            || self.found.what.clone(),
            |h| format!("{} {}", h.display_name(), self.found.what),
        );
        let state = if self.changed { "changed" } else { "is new" };
        let rules = if self.rules.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.rules.join(", "))
        };
        let text = format!(
            "{subject} in {} {state} (not accepted); its command classifies as {}{rules}\n    {}",
            self.found.file.display(),
            self.verdict.as_str(),
            shown(&self.found.commands)
        );
        crate::render::clean_lines(&text)
    }
}

/// The shell classifier's strictest verdict on some commands, and its rules.
pub type Classify<'a> = dyn Fn(&[String]) -> (Verdict, Vec<String>) + 'a;

/// What the ledger found for some hosts.
#[derive(Debug, Default)]
pub struct Review {
    /// `false` when the lock predates the ledger: nothing is held yet.
    pub recorded: bool,
    pub pin_count: usize,
    pub changes: Vec<Change>,
    /// Pins of scanned files whose entry is gone, which accepting drops.
    pub gone: Vec<String>,
    /// The person's `hooks.foreign`: which changes hold the agent's calls.
    pub mode: ForeignHooks,
}

impl Review {
    /// Whether one of the changes holds the agent's calls.
    pub fn holds(&self) -> bool {
        self.changes.iter().any(|c| c.holds(self.mode))
    }
}

/// How the entries `scan` found differ from `pins`, each new or changed one
/// classified by `classify`.
pub fn compare(pins: &Pins, scan: &Scan, classify: &Classify<'_>) -> Review {
    let mut changes = Vec::new();
    let ids: BTreeSet<&str> = scan.found.iter().map(|f| f.id.as_str()).collect();
    for found in &scan.found {
        let was_pinned = match pins.get(&found.id) {
            Some(pin) if pin.digest == found.digest => continue,
            Some(_) => true,
            None => false,
        };
        let (verdict, rules) = if found.commands.is_empty() {
            (Verdict::Review, Vec::new())
        } else {
            classify(&found.commands)
        };
        changes.push(Change {
            found: found.clone(),
            changed: was_pinned,
            verdict,
            rules,
        });
    }
    let gone = pins
        .iter()
        .filter(|(id, pin)| scan.scanned.contains(&pin.file) && !ids.contains(id.as_str()))
        .map(|(id, _)| id.clone())
        .collect();
    Review {
        recorded: true,
        pin_count: pins.len(),
        changes,
        gone,
        mode: ForeignHooks::default(),
    }
}

/// The strictest verdict `compiled` gives `commands` as shell commands, and
/// the rules that gave it.
pub fn classify(compiled: &CompiledPolicy<'_>, commands: &[String]) -> (Verdict, Vec<String>) {
    let mut verdict = Verdict::Allow;
    let mut rules = Vec::new();
    for command in commands {
        let decision = compiled.decide(&Action::Shell {
            command: command.clone(),
        });
        if decision.verdict > verdict {
            verdict = decision.verdict;
            rules.clone_from(&decision.rules);
        }
    }
    (verdict, rules)
}

/// What `hosts` load for a session in `cwd`, compared with `lock`'s ledger,
/// classified by `compiled`.
pub fn review(
    home: &Home,
    lock: &Lock,
    hosts: &[Host],
    cwd: Option<&Path>,
    compiled: &CompiledPolicy<'_>,
) -> Review {
    reviewed(lock, &sources::scan(home, hosts, cwd), compiled)
}

/// What `scan` found, compared with `lock`'s ledger, classified by `compiled`.
fn reviewed(lock: &Lock, scan: &Scan, compiled: &CompiledPolicy<'_>) -> Review {
    let empty = Pins::new();
    let pins = lock.hook_ledger.as_ref().unwrap_or(&empty);
    let mut found = compare(pins, scan, &|commands| classify(compiled, commands));
    found.recorded = lock.hook_ledger.is_some();
    // A repository policy or a pack cannot hold the key, so this is the
    // person's own setting.
    found.mode = compiled.policy().foreign_hooks();
    found
}

/// [`review`] under the person's policy, for `status`, `doctor`, `init` and
/// `hooks accept`, which have no compiled policy of their own. The policy is
/// read and compiled only when an entry is new or changed: only those are
/// classified, and only they read `hooks.foreign`; with nothing to classify
/// (the usual case) the review costs the scan alone.
pub fn review_here(home: &Home, lock: &Lock, hosts: &[Host], cwd: Option<&Path>) -> Result<Review> {
    let scan = sources::scan(home, hosts, cwd);
    review_lazily(lock.hook_ledger.as_ref(), &scan, || {
        let ctx = crate::context::eval_context(home, cwd, None)?;
        let policy = crate::repo::effective_policy(home, &ctx)?;
        let compiled = CompiledPolicy::compile(&policy, &ctx)?;
        Ok(reviewed(lock, &scan, &compiled))
    })
}

/// `scan` compared with `ledger`, by `classified` (which reads the policy)
/// only when an entry is new or changed; otherwise there is nothing to
/// classify and no `hooks.foreign` to read.
fn review_lazily(
    ledger: Option<&Pins>,
    scan: &Scan,
    classified: impl FnOnce() -> Result<Review>,
) -> Result<Review> {
    let empty = Pins::new();
    let pins = ledger.unwrap_or(&empty);
    let unaccepted = scan.found.iter().any(|found| {
        pins.get(&found.id)
            .is_none_or(|pin| pin.digest != found.digest)
    });
    if unaccepted {
        return classified();
    }
    // Every entry is pinned as it is: `compare` classifies none of them.
    let mut found = compare(pins, scan, &|_| (Verdict::Review, Vec::new()));
    found.recorded = ledger.is_some();
    Ok(found)
}

/// The hold for a call of `host` from `cwd`, while something `host` loads,
/// or the repository's git configuration names, is not the accepted one:
/// `deny` when the classifier denies one of the new or changed commands;
/// under `hooks.foreign: hold`, `review` for any other. `None` when nothing
/// holds (a new hook whose command is not denied, by default: `status`,
/// `doctor` and `watch` name it), or the lock predates the ledger.
pub fn violation(
    home: &Home,
    lock: &Lock,
    host: Host,
    cwd: Option<&Path>,
    compiled: &CompiledPolicy<'_>,
) -> Option<Decision> {
    lock.hook_ledger.as_ref()?;
    let found = review(home, lock, &[host], cwd, compiled);
    hold(&found.changes, found.mode)
}

/// The decision that holds calls while those of `changes` that hold under
/// `mode` wait for a person: the strictest of their verdicts, never weaker
/// than `review`; `None` when none holds.
fn hold(changes: &[Change], mode: ForeignHooks) -> Option<Decision> {
    let holding: Vec<&Change> = changes.iter().filter(|c| c.holds(mode)).collect();
    let verdict = holding
        .iter()
        .map(|c| c.verdict.max(Verdict::Review))
        .max()?;
    let mut decision = Decision::new(verdict);
    decision.rules.push(FOREIGN_HOOK.to_owned());
    decision
        .reasons
        .extend(holding.iter().map(|c| c.describe()));
    decision.reasons.push(
        "a person must review it: run `openmoat hooks accept` in a terminal (`openmoat status` \
         lists them)"
            .to_owned(),
    );
    Some(decision)
}

/// `decision` made at least as strict as `hold`: a stricter hold replaces the
/// headline and keeps the earlier reasons as context; a weaker one adds its
/// reasons as context.
pub fn tightened(mut decision: Decision, hold: Option<Decision>) -> Decision {
    let Some(hold) = hold else {
        return decision;
    };
    if decision.verdict > hold.verdict {
        decision.context.extend(hold.reasons);
        return decision;
    }
    if decision.verdict < hold.verdict {
        let earlier = std::mem::take(&mut decision.reasons);
        decision.context.extend(earlier);
        decision.rules.clear();
        decision.verdict = hold.verdict;
    }
    for rule in hold.rules {
        if !decision.rules.contains(&rule) {
            decision.rules.push(rule);
        }
    }
    decision.reasons.extend(hold.reasons);
    decision
}

/// Store `changes` as accepted and drop the pins in `gone`, in the lock at
/// `home`; a lock without a ledger starts one.
pub fn accept(home: &Home, changes: &[Change], gone: &[String]) -> Result<()> {
    let path = home.lock_path();
    let mut lock = Lock::load(&path)?;
    let pins = lock.hook_ledger.get_or_insert_with(Pins::new);
    for change in changes {
        pins.insert(change.found.id.clone(), HookPin::of(&change.found));
    }
    for id in gone {
        pins.remove(id);
    }
    lock.save(&path)
}

/// What [`record_current`] did.
#[derive(Debug, Default)]
pub struct Recorded {
    pub count: usize,
    /// New and changed entries left unaccepted for a person.
    pub held: Vec<Change>,
    /// New and changed entries a person's `init` accepted over an existing
    /// ledger, which `init` names so none is accepted unseen.
    pub accepted: Vec<Change>,
    /// The person's `hooks.foreign`: what `held` does to the agents' calls.
    pub mode: ForeignHooks,
}

/// `init`: record what the set-up hosts load now. With `no_person`, new and
/// changed entries are left for `openmoat hooks accept`, as `init` leaves MCP
/// definitions (ADR-026): recording them unseen would accept a hook a cloned
/// project planted. A lock that has no ledger yet records everything found
/// even then, so an upgrade blocks nothing that was there before (ADR-109).
pub fn record_current(
    home: &Home,
    binary: &Path,
    cwd: Option<&Path>,
    no_person: bool,
) -> Result<Recorded> {
    let lock = Lock::load(&home.lock_path())?;
    let hosts = crate::mcp::set_up_hosts(home, binary);
    let found = review_here(home, &lock, &hosts, cwd)?;
    let first = !found.recorded;
    let mode = found.mode;
    let (held, accepted): (Vec<Change>, Vec<Change>) =
        found.changes.into_iter().partition(|_| no_person && !first);
    accept(home, &accepted, &found.gone)?;
    let count = Lock::load(&home.lock_path())?
        .hook_ledger
        .map_or(0, |p| p.len());
    let accepted = if first { Vec::new() } else { accepted };
    Ok(Recorded {
        count,
        held,
        accepted,
        mode,
    })
}

/// What `init`, `status` and `doctor` say the ledger holds: the hook
/// commands, plugin hooks and git programs the set-up agents load besides
/// OpenMoat's own hook. "0 recorded" read as if recording had failed, so none
/// is said as none.
pub fn recorded(count: usize) -> String {
    match count {
        0 => "none besides OpenMoat's own hook".to_owned(),
        n => format!("{n} besides OpenMoat's own hook, recorded"),
    }
}

/// The lines `status`, `doctor` and `hooks list` print for `review`.
pub fn lines(review: &Review) -> Vec<String> {
    if !review.recorded {
        return vec![
            "hooks            the agents' other hook commands are not recorded yet: \
             `openmoat hooks accept` shows them and records them, so a new or changed one is \
             named"
                .to_owned(),
        ];
    }
    review
        .changes
        .iter()
        .map(|change| change.describe().replace('\n', "\n  "))
        .collect()
}

#[cfg(test)]
mod tests;

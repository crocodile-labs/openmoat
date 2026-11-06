//! The running agent's own login under `openmoat run` (ADR-054).
//!
//! The default policy's `agent-credentials` group names where each agent keeps
//! its login, provider keys and OAuth tokens, and every OS sandbox denies them
//! to the commands the agent runs. The agents' own sandboxes (Claude Code's,
//! Codex's, Cursor's) confine only those commands, so the agent itself still
//! reads its login outside them. Under `openmoat run` the agent runs inside the
//! sandbox, so the session's sandbox leaves out the group's patterns that hold
//! the agent's own login: those its host spec names
//! ([`openmoat_hosts::Protect::credentials`]), or, for a program that is no
//! agent OpenMoat knows, the ones inside the `--write` paths the person granted
//! it. Every other agent's login stays denied. The hook keeps deciding with
//! the whole policy, so the agent's own tools still may not read its login.

use openmoat_core::ir::brace_alternatives;
use openmoat_core::{EvalContext, Kind, Policy};
use openmoat_hosts::Host;

use super::Report;
use super::exposure::within;
use super::patterns::push_unique;

/// The default policy's group of the agents' login files.
pub const RULE: &str = "agent-credentials";

/// The allowance that lists the login a session keeps readable.
pub const ALLOWANCE: &str = "run.own-login";

/// Whose login an `openmoat run` session keeps readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// An agent OpenMoat knows: its own login files, as its spec names them.
    Agent(Host),
    /// Any other program: the login files inside its `--write` paths.
    Unknown,
}

impl Owner {
    /// The agent `name` (the command as typed) or `program` (the file it
    /// resolved to) starts, by each host's program names and package
    /// directories.
    pub fn of(name: &str, program: &str) -> Self {
        Host::by_program(name)
            .or_else(|| Host::by_program(program))
            .map_or(Self::Unknown, |(host, _)| Self::Agent(host))
    }
}

/// What a session keeps readable of [`RULE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// Whose login it is.
    pub owner: Owner,
    /// The group's patterns left out of the sandbox, one per brace
    /// alternative, as the policy spells them (`~/…`).
    pub patterns: Vec<String>,
}

/// `policy` for the sandbox of a session `owner` runs in, with `--write`
/// paths `writes` (resolved) in `ctx`: [`RULE`]'s file patterns without those
/// that hold `owner`'s login, and which they were. Only the sandbox is lowered
/// from it; the hook keeps deciding with `policy`. A group marked `hook_only`
/// reaches no sandbox anyway and is left as it is.
pub fn for_session(
    policy: &Policy,
    ctx: &EvalContext,
    owner: Owner,
    writes: &[String],
) -> (Policy, Kept) {
    let own = match owner {
        Owner::Agent(host) => own_patterns(host),
        Owner::Unknown => Vec::new(),
    };
    let ci = crate::context::CASE_INSENSITIVE_PATHS;
    let keep = |pattern: &str| match owner {
        Owner::Agent(_) => own.iter().any(|p| p == pattern),
        Owner::Unknown => {
            !pattern.starts_with('!')
                && ctx.spellings(pattern).iter().any(|spelling| {
                    let base = literal_base(spelling);
                    writes.iter().any(|write| within(base, write, ci))
                })
        }
    };
    let mut policy = policy.clone();
    let mut kept = Vec::new();
    for group in policy
        .deny
        .iter_mut()
        .filter(|g| g.id == RULE && !g.hook_only)
    {
        for list in [&mut group.fs_read, &mut group.fs_write] {
            let expanded: Vec<String> = list.iter().flat_map(|p| brace_alternatives(p)).collect();
            let (out, rest): (Vec<String>, Vec<String>) =
                expanded.into_iter().partition(|p| keep(p));
            for pattern in out {
                push_unique(&mut kept, pattern);
            }
            *list = rest;
        }
    }
    (
        policy,
        Kept {
            owner,
            patterns: kept,
        },
    )
}

/// The patterns `host`'s spec names for its login, one per brace alternative,
/// and for `dir/**` also `dir`, as the generated policy lines name it.
pub fn own_patterns(host: Host) -> Vec<String> {
    let mut out = Vec::new();
    for paths in host.spec().protect.credentials {
        for glob in paths.globs.iter().flat_map(|g| brace_alternatives(g)) {
            if let Some(dir) = glob.strip_suffix("/**") {
                push_unique(&mut out, dir.to_owned());
            }
            push_unique(&mut out, glob);
        }
    }
    out
}

/// The part of `pattern` before its first glob character, without a
/// trailing `/`: the directory or file it names for certain.
fn literal_base(pattern: &str) -> &str {
    let base = pattern
        .split(['*', '?', '[', '{'])
        .next()
        .unwrap_or(pattern);
    match base.trim_end_matches('/') {
        "" => base,
        trimmed => trimmed,
    }
}

/// List what `kept` leaves readable in `report`, spelled as `ctx` expands it,
/// for reads and writes: the agent refreshes its tokens in place.
pub fn report(report: &mut Report, kept: &Kept, ctx: &EvalContext) {
    if kept.patterns.is_empty() {
        return;
    }
    let patterns: Vec<String> = kept
        .patterns
        .iter()
        .flat_map(|p| ctx.spellings(p))
        .collect();
    let message = match kept.owner {
        Owner::Agent(host) => format!(
            "the sandbox holds {} itself, which signs in with these files, so they stay \
             readable and writable here, for the commands it runs too; every other agent's \
             login is denied (`{RULE}`)",
            host.display_name()
        ),
        Owner::Unknown => format!(
            "the program is no agent OpenMoat knows, so the agent logins inside its `--write` \
             paths stay readable and writable here, for the commands it runs too; every other \
             agent's login is denied (`{RULE}`)"
        ),
    };
    for kind in [Kind::FsRead, Kind::FsWrite] {
        report.allowance(kind, ALLOWANCE, patterns.clone(), &message);
    }
}

#[cfg(test)]
mod tests;

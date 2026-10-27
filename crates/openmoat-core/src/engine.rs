//! The decision engine (docs/POLICY.md §4, docs/ARCHITECTURE.md §4).
//!
//! Per atomic action: `deny → allow → ask → defaults`. Across the atomic
//! actions of one tool call: strictest verdict wins. Deny rules are absolute;
//! an allow rule can never override a deny, so "deny by default with holes"
//! is expressed through per-kind `defaults`, never through a deny rule.

use crate::action::{Action, AtomicAction};
use crate::kind::Kind;
use crate::pattern::{GlobPattern, ShellPattern, any_match};
use crate::policy::{Policy, PolicyError, RuleGroup};
use crate::programs::{self, NoResolver, ProgramResolver};
use crate::realpath::PathResolver;
use crate::verdict::{Decision, Verdict};

mod aliases;
mod atoms;
mod contents;
mod context;
mod egress;
mod taint;

use atoms::checked_atoms;
pub use contents::HOLDS_PROTECTED_RULE;
pub use taint::{Secret, TAINT_RULE, Taint};

/// Everything the engine needs from the environment. Supplied by the caller.
#[derive(Debug, Clone)]
pub struct EvalContext {
    /// The user's home directory, for `~` and `$HOME`.
    pub home: String,
    /// The trusted project root, for `${project}`. `None` when the session has
    /// no project the caller is willing to trust (it would be the home directory,
    /// one of its ancestors or a filesystem root): every pattern naming
    /// `${project}` then matches nothing, so project-scoped allows do not apply.
    pub project: Option<String>,
    /// `home` with its symlinks resolved, when that differs (a home on a linked
    /// volume, a Windows 8.3 short name). Patterns naming `~` match under both
    /// spellings, since the caller's [`PathResolver`] reports paths in this one.
    pub real_home: Option<String>,
    /// `project` with its symlinks resolved, when that differs (macOS `/tmp` →
    /// `/private/tmp`, `~/code` → `/Volumes/dev/code`). Patterns naming
    /// `${project}` match under both spellings, exclusions included, so a file
    /// in the project is the project's however its path is written. A link
    /// *inside* the project changes nothing here: its target is checked as is.
    pub real_project: Option<String>,
    /// Directories an environment variable moved out of the home directory
    /// (`MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `CURSOR_CONFIG_DIR`), as
    /// `(default, moved)` pairs such as `("~/.claude", "/srv/claude")`. A
    /// pattern naming `default` or a path below it also matches the same path
    /// under `moved`, so rules about a host's directory follow it when it moves.
    pub moved_dirs: Vec<(String, String)>,
    /// The directory relative paths are taken from.
    pub cwd: String,
    /// Whether file paths compare case-insensitively, as on the default macOS
    /// and Windows file systems. Host names always do; names never do.
    pub case_insensitive_paths: bool,
}

/// A policy with all patterns compiled for one evaluation context.
///
/// Compile once per process (or per policy reload) and reuse for every tool
/// call; compilation dominates the cost of a single decision.
#[derive(Debug)]
pub struct CompiledPolicy<'p> {
    policy: &'p Policy,
    ctx: EvalContext,
    deny: Vec<CompiledGroup<'p>>,
    repo_ask: Vec<CompiledGroup<'p>>,
    allow: Vec<CompiledGroup<'p>>,
    ask: Vec<CompiledGroup<'p>>,
    defer: Vec<CompiledGroup<'p>>,
    /// Paths a write to asks once the session read untrusted content (`taint`).
    protected: Vec<GlobPattern>,
    /// The folders deny rules' paths lie in, which reading or writing asks for.
    folders: contents::ProtectedFolders,
}

#[derive(Debug)]
struct CompiledGroup<'p> {
    group: &'p RuleGroup,
    shell: Vec<ShellPattern>,
    /// Glob patterns per kind, indexed by `Kind as usize`; the shell slot is empty.
    globs: [Vec<GlobPattern>; Kind::ALL.len()],
    /// For an allow group, its `net` and `fetch` patterns without the
    /// `host:port` ones ([`crate::host::port_pattern`]), which a host without a
    /// port is matched against: `*:8443` allows port 8443 of every host to the
    /// proxy, and must not also match an IPv6 address whose text ends in
    /// `:8443`. Deny and ask rules keep them: there they only refuse more.
    bare_hosts: Option<[Vec<GlobPattern>; Kind::ALL.len()]>,
}

/// Whether `pattern` is a `net` or `fetch` pattern written `host:port`, not an
/// exclusion.
fn names_port(pattern: &str) -> bool {
    !pattern.starts_with('!') && crate::host::port_pattern(pattern).is_some()
}

impl<'p> CompiledPolicy<'p> {
    /// Compile every pattern of `policy` for `ctx`. Fails on a pattern that does
    /// not compile, and on a `moved_dirs` entry whose `default` could alias every
    /// pattern (empty, bare `/`, or not an absolute or `~/`-rooted directory).
    pub fn compile(policy: &'p Policy, ctx: &EvalContext) -> Result<Self, PolicyError> {
        ctx.validate_moved_dirs()?;
        let compile_list = |groups: &'p [RuleGroup], allow: bool| {
            groups
                .iter()
                .map(|g| CompiledGroup::compile(g, ctx, allow))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            policy,
            ctx: ctx.clone(),
            deny: compile_list(&policy.deny, false)?,
            repo_ask: compile_list(&policy.repo_ask, false)?,
            allow: compile_list(&policy.allow, true)?,
            ask: compile_list(&policy.ask, false)?,
            defer: compile_list(&policy.defer, false)?,
            protected: taint::compile_protected(policy, ctx)?,
            folders: contents::ProtectedFolders::compile(&policy.deny, ctx),
        })
    }

    /// The policy this was compiled from.
    #[must_use]
    pub fn policy(&self) -> &'p Policy {
        self.policy
    }

    /// The context this was compiled for.
    #[must_use]
    pub fn context(&self) -> &EvalContext {
        &self.ctx
    }

    /// Evaluate one atomic action: deny → allow → ask → defer → default, with a
    /// repository policy's ask rules ([`Policy::repo_ask`]) tried before allow.
    ///
    /// Returns `None` for a whole-pipeline atom that no rule mentions: pipelines
    /// are only there so rules like `curl * | sh` can see across `|`; the
    /// per-sub-command atoms carry the default verdict.
    #[must_use]
    pub fn evaluate_atomic(&self, action: &AtomicAction) -> Option<Decision> {
        if let Some(hit) = self.matched_rules(action) {
            return Some(hit);
        }
        if matches!(action, AtomicAction::Pipeline { .. }) {
            return None;
        }
        let (verdict, rule_id) = self.policy.defaults.for_atom(action);
        Some(Decision::single(
            verdict,
            &rule_id,
            format!("no rule matched {}", action.describe()),
        ))
    }

    /// The first of deny, repository ask, allow, ask and defer whose rules
    /// match `action`, with every matching rule; `None` when no rule does.
    fn matched_rules(&self, action: &AtomicAction) -> Option<Decision> {
        for (groups, verdict) in [
            (&self.deny, Verdict::Deny),
            (&self.repo_ask, Verdict::Ask),
            (&self.allow, Verdict::Allow),
            (&self.ask, Verdict::Ask),
            (&self.defer, Verdict::Defer),
        ] {
            let mut hit = Decision::new(verdict);
            for g in groups {
                if g.matches(action) {
                    let why = g.group.reason.as_ref().map_or_else(
                        || action.describe(),
                        |r| format!("{r}: {}", action.describe()),
                    );
                    hit.push(&g.group.id, why);
                }
            }
            if !hit.rules.is_empty() {
                return Some(hit);
            }
        }
        None
    }
}

impl<'p> CompiledGroup<'p> {
    /// `allow` says whether the group is an allow rule ([`Self::bare_hosts`]).
    fn compile(group: &'p RuleGroup, ctx: &EvalContext, allow: bool) -> Result<Self, PolicyError> {
        let shell = group
            .shell
            .iter()
            .map(|p| ShellPattern::compile(p))
            .collect::<Result<_, _>>()?;
        let mut globs: [Vec<GlobPattern>; Kind::ALL.len()] = Default::default();
        let mut bare: [Vec<GlobPattern>; Kind::ALL.len()] = Default::default();
        for kind in Kind::ALL.into_iter().filter(|k| *k != Kind::Shell) {
            let case_insensitive = match kind {
                Kind::FsRead | Kind::FsWrite => ctx.case_insensitive_paths,
                Kind::Net | Kind::Fetch => true,
                _ => false,
            };
            let compile = |patterns: &mut dyn Iterator<Item = &String>| {
                patterns
                    .flat_map(|p| ctx.spellings(p))
                    .map(|p| GlobPattern::compile(&p, case_insensitive))
                    .collect::<Result<Vec<_>, _>>()
            };
            let patterns = group.patterns(kind);
            globs[kind as usize] = compile(&mut patterns.iter())?;
            if matches!(kind, Kind::Net | Kind::Fetch) {
                bare[kind as usize] = compile(&mut patterns.iter().filter(|p| !names_port(p)))?;
            }
        }
        Ok(Self {
            group,
            shell,
            globs,
            bare_hosts: allow.then_some(bare),
        })
    }

    fn matches(&self, action: &AtomicAction) -> bool {
        match (action, action.subject()) {
            (AtomicAction::Shell { argv } | AtomicAction::Pipeline { argv }, _) => {
                any_match(&self.shell, argv.as_slice())
            }
            (_, Some(subject)) => {
                let globs = match &self.bare_hosts {
                    Some(bare)
                        if matches!(
                            action,
                            AtomicAction::Net { .. } | AtomicAction::Fetch { .. }
                        ) && crate::host::port_pattern(subject).is_none() =>
                    {
                        bare
                    }
                    _ => &self.globs,
                };
                action
                    .kind()
                    .rule_kinds()
                    .iter()
                    .any(|k| any_match(&globs[*k as usize], subject))
            }
            (_, None) => false,
        }
    }
}

impl CompiledPolicy<'_> {
    /// Decide one host action without executable resolution.
    ///
    /// Unparseable input yields the policy's catch-all verdict (`ask` or
    /// `defer`) with the parser's reason, never `allow`.
    #[must_use]
    pub fn decide(&self, action: &Action) -> Decision {
        self.decide_with(action, &NoResolver, &NoResolver)
    }

    /// The atomic actions [`Self::decide_with`] evaluates for `action`, with an
    /// extra atom for every path an unquoted glob operand names in the
    /// directories `paths` lists, and for every read or write `paths` resolves
    /// through a symlink; and the reason when part of the action cannot be
    /// classified or a glob not expanded in full (`ask`).
    #[must_use]
    pub fn atoms(
        &self,
        action: &Action,
        paths: &dyn PathResolver,
    ) -> (Vec<AtomicAction>, Option<String>) {
        let (atoms, unparsed) = self.all_atoms(action, paths);
        (atoms, unparsed.map(|u| u.reason))
    }

    /// [`checked_atoms`] and the atoms of any token or placeholder they send
    /// where it does not belong ([`egress`]).
    fn all_atoms(
        &self,
        action: &Action,
        paths: &dyn PathResolver,
    ) -> (Vec<AtomicAction>, Option<crate::shell::Unparsed>) {
        let (mut atoms, unparsed) = checked_atoms(action, &self.ctx, paths);
        let egress = egress::atoms(action, &atoms, &self.policy.secrets);
        atoms.extend(egress);
        (atoms, unparsed)
    }

    /// The commands of `action` that publish local commits (`git push`, `gh pr
    /// create`), each with the directories it may run in. Only a shell command
    /// has any.
    #[must_use]
    pub fn pushes(&self, action: &Action) -> Vec<crate::shell::push::Push> {
        let Action::Shell { command } = action.shown() else {
            return Vec::new();
        };
        crate::shell::push::pushes(
            command,
            &crate::shell::ShellContext {
                home: &self.ctx.home,
                cwd: &[Some(self.ctx.cwd.clone())],
            },
        )
    }

    /// Decide one host action, resolving shell programs through `resolver` so
    /// that `executables` pins and installation pins are enforced, and paths
    /// through `paths` so a symlink cannot move a read or write past a rule.
    #[must_use]
    pub fn decide_with(
        &self,
        action: &Action,
        resolver: &dyn ProgramResolver,
        paths: &dyn PathResolver,
    ) -> Decision {
        let (atoms, unparsed) = self.all_atoms(action, paths);
        let pins = atoms.iter().filter_map(|atom| match atom {
            AtomicAction::Shell { argv } => {
                programs::check(&argv[0], &self.policy.executables, resolver)
            }
            _ => None,
        });
        // Another spelling of a command (OpenMoat's binary under another name
        // or case) adds the deny or ask its rules give, and nothing else.
        let aliased = aliases::aliases(&atoms, &self.ctx, resolver, paths)
            .into_iter()
            .filter_map(|atom| self.matched_rules(&atom))
            .filter(|hit| matches!(hit.verdict, Verdict::Deny | Verdict::Ask));
        // A part that could not be parsed, or arguments the adapter did not
        // search, may name anything: never allow (defer or ask, ADR-025), and let
        // a deny on the rest still win. A line not read in full, or one past a
        // classifier limit, asks: a deny in what was not read must not defer.
        let verdict = self.policy.defaults.unclassified();
        let unparsed = unparsed.map(|u| {
            let verdict = if u.asks { Verdict::Ask } else { verdict };
            unparseable(
                verdict,
                format!("could not parse action safely: {}", u.reason),
            )
        });
        let unchecked = match action.shown() {
            Action::McpTool {
                unchecked: Some(limit),
                ..
            } => Some(unparseable(
                verdict,
                format!("mcp arguments not fully checked: {limit}"),
            )),
            _ => None,
        };
        // What the payload does not show may be anything: at least `ask`.
        let partial = match action {
            Action::Unchecked { reason, .. } => Some(Decision::single(
                Verdict::Ask,
                crate::action::UNCHECKED_RULE,
                reason.clone(),
            )),
            _ => None,
        };
        // A folder holding paths a deny rule names asks, whatever allows it (ADR-038).
        let folders = atoms.iter().filter_map(|atom| self.folders.decide(atom));
        atoms
            .iter()
            .filter_map(|atom| self.evaluate_atomic(atom))
            .chain(folders)
            .chain(aliased)
            .chain(pins)
            .chain(unparsed)
            .chain(unchecked)
            .chain(partial)
            .reduce(|mut acc, next| {
                acc.merge(next);
                acc
            })
            .unwrap_or_else(|| unparseable(verdict, "action has no evaluable parts".to_owned()))
    }
}

/// Input that cannot be classified: the policy's catch-all, never `allow` (ADR-025).
fn unparseable(verdict: Verdict, reason: String) -> Decision {
    Decision::single(verdict, "unparseable", reason)
}

/// Compile `policy` for `ctx` and decide a single action.
///
/// Convenience for one-shot callers; long-lived callers should keep a
/// [`CompiledPolicy`] instead.
pub fn evaluate(
    policy: &Policy,
    ctx: &EvalContext,
    action: &Action,
) -> Result<Decision, PolicyError> {
    Ok(CompiledPolicy::compile(policy, ctx)?.decide(action))
}

#[cfg(test)]
mod tests;

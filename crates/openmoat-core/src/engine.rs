//! The decision engine (docs/POLICY.md §4, docs/ARCHITECTURE.md §4).
//!
//! Per atomic action: `deny → allow → ask → defaults`. Across the atomic
//! actions of one tool call: strictest verdict wins. Deny rules are absolute;
//! an allow rule can never override a deny, so "deny by default with holes"
//! is expressed through per-kind `defaults`, never through a deny rule.

use crate::action::{Action, AtomicAction};
use crate::expand::Expansion;
use crate::kind::Kind;
use crate::pattern::{GlobPattern, ShellPattern, any_match};
use crate::policy::{Policy, PolicyError, RuleGroup};
use crate::programs::{self, NoResolver, ProgramResolver};
use crate::realpath::{PathResolver, physical};
use crate::shell::{ParseOutcome, ShellContext, classify_globs};
use crate::verdict::{Decision, Verdict};
use crate::{host, paths};

mod context;
mod taint;

pub use taint::{Secret, Taint};

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
}

#[derive(Debug)]
struct CompiledGroup<'p> {
    group: &'p RuleGroup,
    shell: Vec<ShellPattern>,
    /// Glob patterns per kind, indexed by `Kind as usize`; the shell slot is empty.
    globs: [Vec<GlobPattern>; Kind::ALL.len()],
}

impl<'p> CompiledPolicy<'p> {
    /// Compile every pattern of `policy` for `ctx`. Fails on a pattern that does
    /// not compile, and on a `moved_dirs` entry whose `default` could alias every
    /// pattern (empty, bare `/`, or not an absolute or `~/`-rooted directory).
    pub fn compile(policy: &'p Policy, ctx: &EvalContext) -> Result<Self, PolicyError> {
        ctx.validate_moved_dirs()?;
        let compile_list = |groups: &'p [RuleGroup]| {
            groups
                .iter()
                .map(|g| CompiledGroup::compile(g, ctx))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            policy,
            ctx: ctx.clone(),
            deny: compile_list(&policy.deny)?,
            repo_ask: compile_list(&policy.repo_ask)?,
            allow: compile_list(&policy.allow)?,
            ask: compile_list(&policy.ask)?,
            defer: compile_list(&policy.defer)?,
            protected: taint::compile_protected(policy, ctx)?,
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
}

impl<'p> CompiledGroup<'p> {
    fn compile(group: &'p RuleGroup, ctx: &EvalContext) -> Result<Self, PolicyError> {
        let shell = group
            .shell
            .iter()
            .map(|p| ShellPattern::compile(p))
            .collect::<Result<_, _>>()?;
        let mut globs: [Vec<GlobPattern>; Kind::ALL.len()] = Default::default();
        for kind in Kind::ALL.into_iter().filter(|k| *k != Kind::Shell) {
            let case_insensitive = match kind {
                Kind::FsRead | Kind::FsWrite => ctx.case_insensitive_paths,
                Kind::Net | Kind::Fetch => true,
                _ => false,
            };
            globs[kind as usize] = group
                .patterns(kind)
                .iter()
                .flat_map(|p| ctx.spellings(p))
                .map(|p| GlobPattern::compile(&p, case_insensitive))
                .collect::<Result<_, _>>()?;
        }
        Ok(Self {
            group,
            shell,
            globs,
        })
    }

    fn matches(&self, action: &AtomicAction) -> bool {
        match (action, action.subject()) {
            (AtomicAction::Shell { argv } | AtomicAction::Pipeline { argv }, _) => {
                any_match(&self.shell, argv.as_slice())
            }
            (_, Some(subject)) => action
                .kind()
                .rule_kinds()
                .iter()
                .any(|k| any_match(&self.globs[*k as usize], subject)),
            (_, None) => false,
        }
    }
}

/// Classify an [`Action`] into atomic actions for the given context, and list
/// the reads and writes among them whose path is a glob the shell expands.
#[must_use]
pub fn classify_action(action: &Action, ctx: &EvalContext) -> (ParseOutcome, Vec<AtomicAction>) {
    let outcome = match action {
        Action::Shell { command } => {
            return classify_globs(
                command,
                &ShellContext {
                    home: &ctx.home,
                    project: ctx.project.as_deref(),
                    cwd: &[Some(ctx.cwd.clone())],
                },
            );
        }
        Action::ForeignShell { shell, .. } => ParseOutcome::Unparseable {
            reason: format!("{shell} commands are not parsed; only POSIX shell is classified"),
            atoms: Vec::new(),
        },
        Action::FsRead { path } => ParseOutcome::Parsed(file_atoms(path, ctx, read).collect()),
        Action::FsWrite { path } => ParseOutcome::Parsed(file_atoms(path, ctx, write).collect()),
        Action::Patch { writes } if writes.is_empty() => ParseOutcome::Unparseable {
            reason: "patch names no files".to_owned(),
            atoms: Vec::new(),
        },
        Action::Patch { writes } => ParseOutcome::Parsed(
            writes
                .iter()
                .flat_map(|p| file_atoms(p, ctx, write))
                .collect(),
        ),
        Action::ReadFiles { paths } if paths.is_empty() => ParseOutcome::Unparseable {
            reason: "read names no files".to_owned(),
            atoms: Vec::new(),
        },
        Action::ReadFiles { paths } => ParseOutcome::Parsed(
            paths
                .iter()
                .flat_map(|p| file_atoms(p, ctx, read))
                .collect(),
        ),
        Action::Net { url } => match host::of_url(url) {
            Some(host) => ParseOutcome::Parsed(vec![AtomicAction::Net { host }]),
            None => ParseOutcome::Unparseable {
                reason: format!("no host in url `{url}`"),
                atoms: Vec::new(),
            },
        },
        Action::Fetch { url } => match host::of_url(url) {
            Some(host) => ParseOutcome::Parsed(vec![AtomicAction::Fetch { host }]),
            None => ParseOutcome::Unparseable {
                reason: format!("no host in url `{url}`"),
                atoms: Vec::new(),
            },
        },
        Action::WebSearch { query } => ParseOutcome::Parsed(vec![AtomicAction::WebSearch {
            query: query.clone(),
        }]),
        Action::UnknownTool { host, tool } => {
            ParseOutcome::Parsed(vec![AtomicAction::UnknownTool {
                host: host.clone(),
                tool: tool.clone(),
            }])
        }
        Action::McpTool {
            name,
            reads,
            writes,
            hosts,
            ..
        } => {
            let mut atoms = vec![AtomicAction::McpTool { name: name.clone() }];
            atoms.extend(reads.iter().flat_map(|p| file_atoms(p, ctx, read)));
            atoms.extend(writes.iter().flat_map(|p| file_atoms(p, ctx, write)));
            let mut bad_host = None;
            for host in hosts {
                match host::of_url(host) {
                    Some(host) => atoms.push(AtomicAction::Net { host }),
                    None => bad_host = bad_host.or(Some(host)),
                }
            }
            match bad_host {
                Some(host) => ParseOutcome::Unparseable {
                    reason: format!("no host in mcp argument `{host}`"),
                    atoms,
                },
                None => ParseOutcome::Parsed(atoms),
            }
        }
    };
    (outcome, Vec::new())
}

/// The atoms of `action` in `ctx` with an extra atom for every path a glob
/// operand names (`crate::expand`) and for every read or write `paths`
/// resolves through a symlink, and why part of the action cannot be checked.
fn checked_atoms(
    action: &Action,
    ctx: &EvalContext,
    paths: &dyn PathResolver,
) -> (Vec<AtomicAction>, Option<String>) {
    let (outcome, globs) = classify_action(action, ctx);
    let (mut atoms, unparsed) = outcome.into_parts();
    let mut expansion = Expansion::new(paths);
    for glob in &globs {
        if let Some(pattern) = glob.subject() {
            // a glob that kept its `..` is listed where the OS would look
            let pattern = if paths::has_dotdot(pattern) {
                physical(pattern, paths)
            } else {
                pattern.to_owned()
            };
            let named = expansion.paths(&pattern);
            atoms.extend(named.into_iter().filter_map(|path| glob.with_path(path)));
        }
    }
    let unexpanded = expansion.overflow();
    let atoms = with_environ_reads(with_resolved_paths(atoms, paths));
    (atoms, unparsed.or(unexpanded))
}

/// Add `@proc-environ <path>` for every read of a process's environment
/// (`/proc/self/environ`, `/proc/1/task/1/environ`): the same variables as
/// `printenv`, secrets included, which `env-dump` denies. A shell atom, not a
/// path rule, so no OS sandbox is asked to deny a glob under `/proc`.
fn with_environ_reads(atoms: Vec<AtomicAction>) -> Vec<AtomicAction> {
    let environ: Vec<AtomicAction> = atoms
        .iter()
        .filter_map(|atom| match atom {
            AtomicAction::FsRead { path } if is_proc_environ(path) => Some(AtomicAction::Shell {
                argv: vec!["@proc-environ".to_owned(), path.clone()],
            }),
            _ => None,
        })
        .collect();
    atoms.into_iter().chain(environ).collect()
}

/// `/proc/<pid>/environ` or `/proc/<pid>/task/<tid>/environ`, any spelling of the ids.
fn is_proc_environ(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    let id = |s: &str| !s.is_empty();
    match parts.as_slice() {
        ["", "proc", pid, "environ"] => id(pid),
        ["", "proc", pid, "task", tid, "environ"] => id(pid) && id(tid),
        _ => false,
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
        checked_atoms(action, &self.ctx, paths)
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
        let (atoms, unparsed) = self.atoms(action, paths);
        let pins = atoms.iter().filter_map(|atom| match atom {
            AtomicAction::Shell { argv } => {
                programs::check(&argv[0], &self.policy.executables, resolver)
            }
            _ => None,
        });
        // A part that could not be parsed, or arguments the adapter did not
        // search, may name anything: never allow (defer or ask, ADR-025), and let
        // a deny on the rest still win.
        let verdict = self.policy.defaults.unclassified();
        let unparsed = unparsed
            .map(|reason| unparseable(verdict, format!("could not parse action safely: {reason}")));
        let unchecked = match action {
            Action::McpTool {
                unchecked: Some(limit),
                ..
            } => Some(unparseable(
                verdict,
                format!("mcp arguments not fully checked: {limit}"),
            )),
            _ => None,
        };
        atoms
            .iter()
            .filter_map(|atom| self.evaluate_atomic(atom))
            .chain(pins)
            .chain(unparsed)
            .chain(unchecked)
            .reduce(|mut acc, next| {
                acc.merge(next);
                acc
            })
            .unwrap_or_else(|| unparseable(verdict, "action has no evaluable parts".to_owned()))
    }
}

/// The read or write of a file a tool names: its collapsed path, and the form
/// that kept its `..`, if any, for [`with_resolved_paths`] to follow.
fn file_atoms(
    raw: &str,
    ctx: &EvalContext,
    atom: fn(String) -> AtomicAction,
) -> impl Iterator<Item = AtomicAction> {
    let project = ctx.project.as_deref();
    let collapsed = paths::normalise(raw, &ctx.home, project, &ctx.cwd);
    let traversal = paths::traversal(raw, &ctx.home, project, Some(&ctx.cwd));
    std::iter::once(atom(collapsed)).chain(traversal.map(atom))
}

fn read(path: String) -> AtomicAction {
    AtomicAction::FsRead { path }
}

fn write(path: String) -> AtomicAction {
    AtomicAction::FsWrite { path }
}

/// The path of a read or write atom.
fn file_path(atom: &AtomicAction) -> Option<&str> {
    match atom {
        AtomicAction::FsRead { path } | AtomicAction::FsWrite { path } => Some(path),
        _ => None,
    }
}

/// Add an atom for the resolved path of every read and write that goes
/// through a symlink. The literal atom stays: a rule may name either location.
/// A path that kept its `..` ([`paths::traversal`]) is not checked as
/// written: it is replaced by where the OS lands ([`physical`]), since each
/// `..` steps up from where a symlink before it points.
fn with_resolved_paths(atoms: Vec<AtomicAction>, paths: &dyn PathResolver) -> Vec<AtomicAction> {
    let atoms: Vec<AtomicAction> = atoms
        .into_iter()
        .filter_map(|atom| match file_path(&atom) {
            Some(path) if paths::has_dotdot(path) => atom.with_path(physical(path, paths)),
            _ => Some(atom),
        })
        .collect();
    let resolved: Vec<AtomicAction> = atoms
        .iter()
        .filter_map(|atom| {
            let (AtomicAction::FsRead { path } | AtomicAction::FsWrite { path }) = atom else {
                return None;
            };
            atom.with_path(paths.resolve(path).filter(|real| real != path)?)
        })
        .collect();
    atoms.into_iter().chain(resolved).collect()
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

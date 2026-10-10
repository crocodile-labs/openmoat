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
use crate::realpath::PathResolver;
use crate::shell::{ParseOutcome, ShellContext, classify_globs};
use crate::verdict::{Decision, Verdict};
use crate::{host, paths};

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

    /// Evaluate one atomic action: deny → allow → ask → default, with a
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
        let (verdict, rule_id) = self.policy.defaults.for_kind(action.kind());
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

impl EvalContext {
    /// Reject [`Self::moved_dirs`] entries whose `default` could alias every
    /// pattern body (empty-after-trim or a bare `/`) or does not look like a
    /// directory (must start with `/` or `~/`). The engine fails closed on such
    /// a context: without validation an empty `default` makes [`Self::spellings`]
    /// emit a spelling under `moved` for every pattern (#399), so a `moved_dirs`
    /// mistake in the caller would silently widen every rule. The CLI legitimately
    /// lists the same `default` twice when the moved directory has a resolved
    /// spelling or comes from both the environment and the recorded host dir,
    /// so a duplicate `default` is kept (its spellings deduped in [`Self::spellings`]).
    pub(crate) fn validate_moved_dirs(&self) -> Result<(), PolicyError> {
        for (default, _) in &self.moved_dirs {
            let trimmed = default.trim();
            let valid = !trimmed.is_empty()
                && trimmed != "/"
                && (trimmed == "~" || trimmed.starts_with("~/") || paths::is_absolute(trimmed));
            if !valid {
                return Err(PolicyError::Rule {
                    rule: "context.moved_dirs".to_owned(),
                    problem: format!(
                        "default directory `{default}` must be absolute (`/…`) or home-rooted (`~/…`), \
                         not empty, whitespace or a bare `/`"
                    ),
                });
            }
        }
        Ok(())
    }

    /// `raw` expanded once per spelling of the home directory and project root
    /// it names ([`paths::expand_pattern`]), and once more per directory in
    /// [`Self::moved_dirs`] it falls under; empty when it names no location.
    /// The policy compiler (`ir`) lowers patterns through the same expansion.
    pub(crate) fn spellings(&self, raw: &str) -> Vec<String> {
        let (negated, body) = crate::pattern::split_negation(raw);
        let bang = if negated { "!" } else { "" };
        let moved = self.moved_dirs.iter().filter_map(|(default, dir)| {
            let rest = body.strip_prefix(default.as_str())?;
            (rest.is_empty() || rest.starts_with('/')).then(|| format!("{bang}{dir}{rest}"))
        });
        let raws: Vec<String> = std::iter::once(raw.to_owned()).chain(moved).collect();
        let projects: Vec<Option<&str>> = match &self.project {
            Some(p) => [Some(p), self.real_project.as_ref()]
                .into_iter()
                .flatten()
                .map(|p| Some(p.as_str()))
                .collect(),
            None => vec![None],
        };
        let mut out = Vec::new();
        for home in [Some(&self.home), self.real_home.as_ref()]
            .into_iter()
            .flatten()
        {
            for project in &projects {
                out.extend(
                    raws.iter()
                        .filter_map(|raw| paths::expand_pattern(raw, home, *project)),
                );
            }
        }
        out.sort();
        out.dedup();
        out
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
        Action::FsRead { path } => ParseOutcome::Parsed(vec![AtomicAction::FsRead {
            path: paths::normalise(path, &ctx.home, ctx.project.as_deref(), &ctx.cwd),
        }]),
        Action::FsWrite { path } => ParseOutcome::Parsed(vec![AtomicAction::FsWrite {
            path: paths::normalise(path, &ctx.home, ctx.project.as_deref(), &ctx.cwd),
        }]),
        Action::Patch { writes } if writes.is_empty() => ParseOutcome::Unparseable {
            reason: "patch names no files".to_owned(),
            atoms: Vec::new(),
        },
        Action::Patch { writes } => ParseOutcome::Parsed(
            writes
                .iter()
                .map(|p| AtomicAction::FsWrite {
                    path: paths::normalise(p, &ctx.home, ctx.project.as_deref(), &ctx.cwd),
                })
                .collect(),
        ),
        Action::ReadFiles { paths } if paths.is_empty() => ParseOutcome::Unparseable {
            reason: "read names no files".to_owned(),
            atoms: Vec::new(),
        },
        Action::ReadFiles { paths } => ParseOutcome::Parsed(
            paths
                .iter()
                .map(|p| AtomicAction::FsRead {
                    path: paths::normalise(p, &ctx.home, ctx.project.as_deref(), &ctx.cwd),
                })
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
        Action::McpTool {
            name,
            reads,
            writes,
            hosts,
            ..
        } => {
            let norm =
                |p: &String| paths::normalise(p, &ctx.home, ctx.project.as_deref(), &ctx.cwd);
            let mut atoms = vec![AtomicAction::McpTool { name: name.clone() }];
            atoms.extend(reads.iter().map(|p| AtomicAction::FsRead { path: norm(p) }));
            atoms.extend(
                writes
                    .iter()
                    .map(|p| AtomicAction::FsWrite { path: norm(p) }),
            );
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
            let named = expansion.paths(pattern);
            atoms.extend(named.into_iter().filter_map(|path| glob.with_path(path)));
        }
    }
    let unexpanded = expansion.overflow();
    (with_resolved_paths(atoms, paths), unparsed.or(unexpanded))
}

impl CompiledPolicy<'_> {
    /// Decide one host action without executable resolution.
    ///
    /// Unparseable input yields `ask` with the parser's reason, never `allow`.
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
        // search, may name anything: ask, and let a deny on the rest still win.
        let unparsed =
            unparsed.map(|reason| unparseable(format!("could not parse action safely: {reason}")));
        let unchecked = match action {
            Action::McpTool {
                unchecked: Some(limit),
                ..
            } => Some(unparseable(format!(
                "mcp arguments not fully checked: {limit}"
            ))),
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
            .unwrap_or_else(|| unparseable("action has no evaluable parts".to_owned()))
    }
}

/// Add an atom for the resolved path of every read and write that goes
/// through a symlink. The literal atom stays: a rule may name either location.
fn with_resolved_paths(atoms: Vec<AtomicAction>, paths: &dyn PathResolver) -> Vec<AtomicAction> {
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

fn unparseable(reason: String) -> Decision {
    Decision::single(Verdict::Ask, "unparseable", reason)
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

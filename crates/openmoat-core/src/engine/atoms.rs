//! From an [`Action`] to the atomic actions the policy decides: the shell
//! classifier for commands, one read or write per file a tool names, the
//! files an unquoted glob names, and the resolved path of every read or write
//! that goes through a symlink.

use super::EvalContext;
use crate::action::{Action, AtomicAction};
use crate::expand::Expansion;
use crate::realpath::{PathResolver, physical};
use crate::shell::{ParseOutcome, ShellContext, Unparsed, classify_globs};
use crate::{host, paths};

/// Classify an [`Action`] into atomic actions for the given context, and list
/// the reads and writes among them whose path is a glob the shell expands.
fn classify_action(action: &Action, ctx: &EvalContext) -> (ParseOutcome, Vec<AtomicAction>) {
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
            asks: false,
        },
        Action::FsRead { path } => ParseOutcome::Parsed(file_atoms(path, ctx, read).collect()),
        Action::FsWrite { path } => ParseOutcome::Parsed(file_atoms(path, ctx, write).collect()),
        Action::Patch { writes } if writes.is_empty() => ParseOutcome::Unparseable {
            reason: "patch names no files".to_owned(),
            atoms: Vec::new(),
            asks: false,
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
            asks: false,
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
                asks: false,
            },
        },
        Action::Fetch { url } => match host::of_url(url) {
            Some(host) => ParseOutcome::Parsed(vec![AtomicAction::Fetch { host }]),
            None => ParseOutcome::Unparseable {
                reason: format!("no host in url `{url}`"),
                atoms: Vec::new(),
                asks: false,
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
                    asks: false,
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
pub(super) fn checked_atoms(
    action: &Action,
    ctx: &EvalContext,
    paths: &dyn PathResolver,
) -> (Vec<AtomicAction>, Option<Unparsed>) {
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
    let unexpanded = expansion.overflow().map(|reason| Unparsed {
        reason,
        asks: false,
    });
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

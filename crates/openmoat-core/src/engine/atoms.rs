//! From an [`Action`] to the atomic actions the policy decides: the shell
//! classifier for commands, one read or write per file a tool names, the
//! files an unquoted glob names, and the resolved path of every read or write
//! that goes through a symlink.

use super::EvalContext;
use crate::action::{Action, AtomicAction};
use crate::expand::Expansion;
use crate::host::web;
use crate::paths;
use crate::realpath::{PathResolver, physical};
use crate::shell::{ParseOutcome, ShellContext, Unparsed, classify_globs};

mod urls;

/// How an MCP call that only opens a page is decided (`mcp.browser_open`,
/// ADR-047): as a `fetch` of a plain web page, or as a `net` connection.
#[derive(Debug, Clone, Copy)]
pub(super) struct Opens {
    pub(super) as_fetch: bool,
}

/// Classify an [`Action`] into atomic actions for the given context, and list
/// the reads and writes among them whose path is a glob the shell expands.
fn classify_action(
    action: &Action,
    ctx: &EvalContext,
    opens_as: Opens,
) -> (ParseOutcome, Vec<(AtomicAction, bool)>) {
    let outcome = match action {
        Action::Shell { command } => {
            return classify_globs(
                command,
                &ShellContext {
                    home: &ctx.home,
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
        // every host a client may read the URL as reaching (`host::web`)
        Action::Net { url } | Action::Fetch { url } => match web::readings(url) {
            hosts if hosts.is_empty() => ParseOutcome::Unparseable {
                reason: format!("no host in url `{url}`"),
                atoms: Vec::new(),
                asks: false,
            },
            hosts => ParseOutcome::Parsed(
                hosts
                    .into_iter()
                    .map(|host| match action {
                        Action::Fetch { .. } => AtomicAction::Fetch { host },
                        _ => AtomicAction::Net { host },
                    })
                    .collect(),
            ),
        },
        Action::WebSearch { query } => ParseOutcome::Parsed(vec![AtomicAction::WebSearch {
            query: query.clone(),
        }]),
        Action::UnknownTool {
            host,
            tool,
            reads,
            writes,
            hosts,
            commands,
        } => {
            let first = AtomicAction::UnknownTool {
                host: host.clone(),
                tool: tool.clone(),
            };
            let named = Named {
                reads,
                writes,
                hosts,
                opens: &[],
                commands,
            };
            return named.atoms(first, "tool", ctx, opens_as);
        }
        Action::McpTool {
            name,
            reads,
            writes,
            hosts,
            opens,
            commands,
            ..
        } => {
            let first = AtomicAction::McpTool { name: name.clone() };
            let named = Named {
                reads,
                writes,
                hosts,
                opens,
                commands,
            };
            return named.atoms(first, "mcp", ctx, opens_as);
        }
        Action::Unchecked { action, .. } => return classify_action(action, ctx, opens_as),
    };
    (outcome, Vec::new())
}

/// What a tool's arguments name: the paths, hosts and shell commands an
/// adapter found in them (MCP and unknown tools).
struct Named<'a> {
    reads: &'a [String],
    writes: &'a [String],
    hosts: &'a [String],
    /// The page a read-only call opens (MCP `opens`, ADR-047).
    opens: &'a [String],
    commands: &'a [String],
}

impl Named<'_> {
    /// `first` (the tool's own atom) and the atoms of everything named, with
    /// the globs the commands' shell expands. `what` names the arguments in a
    /// reason (`mcp argument`).
    fn atoms(
        &self,
        first: AtomicAction,
        what: &str,
        ctx: &EvalContext,
        opens_as: Opens,
    ) -> (ParseOutcome, Vec<(AtomicAction, bool)>) {
        let mut atoms = vec![first];
        atoms.extend(self.reads.iter().flat_map(|p| file_atoms(p, ctx, read)));
        atoms.extend(self.writes.iter().flat_map(|p| file_atoms(p, ctx, write)));
        let mut unparsed: Option<Unparsed> = None;
        let mut note = |why: Option<Unparsed>| {
            // a URL that asks wins over one that only cannot be read
            if let Some(why) = why
                && (why.asks || unparsed.is_none())
                && !unparsed.as_ref().is_some_and(|u| u.asks)
            {
                unparsed = Some(why);
            }
        };
        for url in self.hosts {
            note(urls::named(url, what, ctx, &mut atoms));
        }
        for url in self.opens {
            note(urls::opened(url, opens_as.as_fetch, ctx, &mut atoms));
        }
        let mut globs = Vec::new();
        let cwd = [Some(ctx.cwd.clone())];
        let shell = ShellContext {
            home: &ctx.home,
            cwd: &cwd,
        };
        for command in self.commands {
            let (outcome, expanded) = classify_globs(command, &shell);
            globs.extend(expanded);
            let (found, why) = outcome.into_parts();
            atoms.extend(found);
            if let Some(why) = why {
                // a line not read in full asks, whichever part said so
                let asks = why.asks || unparsed.as_ref().is_some_and(|u| u.asks);
                let reason = unparsed.take().map_or(why.reason, |u| u.reason);
                unparsed = Some(Unparsed { reason, asks });
            }
        }
        let outcome = match unparsed {
            Some(Unparsed { reason, asks }) => ParseOutcome::Unparseable {
                reason,
                atoms,
                asks,
            },
            None => ParseOutcome::Parsed(atoms),
        };
        (outcome, globs)
    }
}

/// The atoms of `action` in `ctx` with an extra atom for every path a glob
/// operand names (`crate::expand`) and for every read or write `paths`
/// resolves through a symlink, and why part of the action cannot be checked.
pub(super) fn checked_atoms(
    action: &Action,
    ctx: &EvalContext,
    opens_as: Opens,
    paths: &dyn PathResolver,
) -> (Vec<AtomicAction>, Option<Unparsed>) {
    let (outcome, globs) = classify_action(action, ctx, opens_as);
    let (mut atoms, unparsed) = outcome.into_parts();
    let mut expansion = Expansion::new(paths);
    for (glob, dot_dirs) in &globs {
        if let Some(pattern) = glob.subject() {
            // a glob that kept its `..` is listed where the OS would look
            let pattern = if paths::has_dotdot(pattern) {
                physical(pattern, paths)
            } else {
                pattern.to_owned()
            };
            let named = expansion.paths(&pattern, *dot_dirs);
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

/// The files the shell command `command` runs as code (`shell/executes.rs`),
/// as canonical paths: a glob word as the files it names, a `..` where the OS
/// lands, and a path through a symlink also as where it points, so a file is
/// found under any of the names a write of it was recorded with.
pub(super) fn executed_files(
    command: &str,
    ctx: &EvalContext,
    paths: &dyn PathResolver,
) -> Vec<String> {
    let cwd = [Some(ctx.cwd.clone())];
    let shell = ShellContext {
        home: &ctx.home,
        cwd: &cwd,
    };
    let mut expansion = Expansion::new(paths);
    let mut atoms = Vec::new();
    for (path, glob) in crate::shell::executes::executed(command, &shell) {
        if glob {
            let pattern = if paths::has_dotdot(&path) {
                physical(&path, paths)
            } else {
                path.clone()
            };
            atoms.extend(
                expansion
                    .paths(&pattern, true)
                    .into_iter()
                    .map(|path| AtomicAction::FsRead { path }),
            );
        }
        atoms.push(AtomicAction::FsRead { path });
    }
    let mut files: Vec<String> = with_resolved_paths(atoms, paths)
        .into_iter()
        .filter_map(|atom| match atom {
            AtomicAction::FsRead { path } => Some(path),
            _ => None,
        })
        .collect();
    files.sort_unstable();
    files.dedup();
    files
}

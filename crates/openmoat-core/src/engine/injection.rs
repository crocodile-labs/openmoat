//! Injected input (ADR-057): which call outputs are untrusted, what of them is
//! kept, and how a later call that acts on it is tightened.
//!
//! Only tightens: a later shell command or write whose network target, path
//! or command came from untrusted content needs review, unless the policy
//! allows that part of it outright (a host on the allow list, a project
//! file, `cargo build`). A fetch, a search, an MCP call or an unknown tool
//! is not checked: following a link or a search result is how reading works,
//! and the host's own prompt decides those (`fetch: defer`).

use super::{CompiledPolicy, EvalContext, UntrustedKind, checked_atoms};
use crate::action::{Action, AtomicAction};
use crate::injection::{
    self, InjectedLookup, MAX_COMMAND_LEN, MAX_TOKENS_PER_OUTPUT, MIN_COMMAND_LEN, Token, TokenKind,
};
use crate::programs::NoResolver;
use crate::realpath::PathResolver;
use crate::verdict::{Decision, Verdict};

/// Programs whose output is text from a forge's issues, pull requests and
/// comments, which anyone may write: their hosts are on the allow list
/// (`registries`), so they are named here.
const REMOTE_TEXT_PROGRAMS: [&str; 3] = ["gh", "glab", "tea"];

/// The longest source description kept with a token.
const MAX_SOURCE_LEN: usize = 200;

impl CompiledPolicy<'_> {
    /// What the output of `action`, run in `cwd`, is, when it is content an
    /// attacker may control (`fetch https://docs.example/page`): what session
    /// taint calls untrusted (a fetch, a web search, an MCP result, an unknown
    /// tool; a metadata tool too, which does not taint the session, since a
    /// page sets the title and URL a tab list shows), and a shell command that
    /// reads from a network host the policy does not allow or from a forge's
    /// command-line client (`gh issue view`). `None` for everything else: a
    /// read of a file, a local command.
    #[must_use]
    pub fn output_source(
        &self,
        action: &Action,
        cwd: &str,
        paths: &dyn PathResolver,
    ) -> Option<String> {
        let ctx = EvalContext {
            cwd: cwd.to_owned(),
            ..self.ctx.clone()
        };
        let (atoms, _) = checked_atoms(action, &ctx, self.opens_as(), paths);
        if let Some(exposed) = atoms.iter().find(|atom| UntrustedKind::of(atom).is_some()) {
            let source = match action.shown() {
                Action::Fetch { url } => format!("the page fetched from {url}"),
                Action::WebSearch { query } => format!("the web search results for \"{query}\""),
                Action::McpTool { name, .. } => format!("the result of MCP tool {name}"),
                Action::UnknownTool { tool, .. } => format!("the output of tool {tool}"),
                Action::Shell { command } => format!("the output of `{command}`"),
                _ => exposed.describe(),
            };
            return Some(cut(source));
        }
        let command = match action.shown() {
            Action::Shell { command } => command,
            Action::ForeignShell { command, .. } => {
                return self
                    .foreign_reads_remote(command)
                    .then(|| cut(format!("the output of `{command}`")));
            }
            _ => return None,
        };
        let reads_remote = atoms.iter().any(|atom| match atom {
            AtomicAction::Net { host } | AtomicAction::Fetch { host } => {
                !crate::host::is_loopback(host) && !self.allows(atom)
            }
            AtomicAction::Shell { argv } => argv
                .first()
                .is_some_and(|p| REMOTE_TEXT_PROGRAMS.contains(&program_name(p))),
            _ => false,
        });
        reads_remote.then(|| cut(format!("the output of `{command}`")))
    }

    /// The tokens of `output`, the output of `source` (an action
    /// [`Self::output_source`] names), worth keeping: hosts other than the
    /// ones `source` itself reached and than loopback, absolute paths outside
    /// the project, and commands of its code spans as the classifier reads
    /// them. Hosts are kept in their canonical spelling
    /// (`host::canonical`, ADR-063 §4), as a later call's hosts are
    /// compared. De-duplicated, at most [`MAX_TOKENS_PER_OUTPUT`]: URL hosts
    /// first, then commands, paths, and words that look like hosts.
    #[must_use]
    pub fn injected_tokens(&self, source: &Action, cwd: &str, output: &str) -> Vec<Token> {
        let found = injection::candidates(output);
        let ctx = EvalContext {
            cwd: cwd.to_owned(),
            ..self.ctx.clone()
        };
        let (source_atoms, _) = checked_atoms(source, &ctx, self.opens_as(), &NoResolver);
        // Never kept, so never a parent a later call links to (ADR-063 §4):
        // `docs.github.com` named by a page on `github.com` links nothing new.
        let foreign_hosts = match source.shown() {
            Action::ForeignShell { command, .. } => foreign::named(command).hosts,
            _ => Vec::new(),
        };
        let own_hosts: Vec<String> = source_atoms
            .iter()
            .filter_map(host_of)
            .chain(foreign_hosts.iter().map(String::as_str))
            .map(crate::host::canonical)
            .collect();
        let host_token = |kind: TokenKind| {
            let own_hosts = &own_hosts;
            move |host: String| {
                let text = crate::host::canonical(&host);
                let foreign = !own_hosts.contains(&text) && !crate::host::is_loopback(&host);
                foreign.then_some(Token { kind, text })
            }
        };
        let commands = found
            .commands
            .iter()
            .flat_map(|line| self.commands_of(line, &ctx));
        let paths = found.paths.iter().filter_map(|raw| {
            let path = crate::paths::resolve(raw, &ctx.home, ctx.project.as_deref(), None)?;
            (path.len() > 1 && !self.in_project(&path)).then(|| Token {
                kind: TokenKind::Path,
                text: self.path_key(&path),
            })
        });
        let mut tokens: Vec<Token> = Vec::new();
        let all = found
            .url_hosts
            .into_iter()
            .filter_map(host_token(TokenKind::UrlHost))
            .chain(commands)
            .chain(paths)
            .chain(
                found
                    .word_hosts
                    .into_iter()
                    .filter_map(host_token(TokenKind::WordHost)),
            );
        for token in all {
            if tokens.len() >= MAX_TOKENS_PER_OUTPUT {
                break;
            }
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
        tokens
    }

    /// `decision` for `action`, tightened by the tokens of untrusted content
    /// `seen` knows: a shell command or a write needs review when a host it
    /// reaches, a file it writes or a command it runs came from that content,
    /// and the policy does not allow that atom. A command counts only when the
    /// call also reaches a host or a file outside the project that the policy
    /// does not allow. A command of a shell the classifier cannot read
    /// (PowerShell) is checked on its text: a host or a path outside the
    /// project it names ([`foreign`]). Never loosens; a deny stays.
    #[must_use]
    pub fn with_injected(
        &self,
        decision: Decision,
        action: &Action,
        paths: &dyn PathResolver,
        seen: &dyn InjectedLookup,
    ) -> Decision {
        let checked = matches!(
            action.shown(),
            Action::Shell { .. }
                | Action::ForeignShell { .. }
                | Action::FsWrite { .. }
                | Action::Patch { .. }
        );
        if !checked || decision.verdict == Verdict::Deny {
            return decision;
        }
        if let Action::ForeignShell { command, .. } = action.shown() {
            return planted(decision, self.foreign_injected(command, seen));
        }
        let (atoms, _) = self.atoms(action, paths);
        // A command copied from the content counts only when it reaches past
        // what the policy allows outside the project: a host or a file. Docs
        // tell people to run `git push origin main`; that is daily work.
        let reaches_outside = atoms.iter().any(|atom| match atom {
            AtomicAction::Net { .. } | AtomicAction::Fetch { .. } => !self.allows(atom),
            AtomicAction::FsRead { path } | AtomicAction::FsWrite { path } => {
                !self.in_project(path) && !self.allows(atom)
            }
            _ => false,
        });
        let found = atoms
            .iter()
            .filter(|atom| reaches_outside || !matches!(atom, AtomicAction::Shell { .. }))
            .filter_map(|atom| self.injected(atom, seen))
            .collect();
        planted(decision, found)
    }

    /// The part of `atom` that came from untrusted content, unless the policy
    /// allows the atom; `None` when no part did.
    fn injected(&self, atom: &AtomicAction, seen: &dyn InjectedLookup) -> Option<Found> {
        let (token, source) = match atom {
            AtomicAction::Net { host } | AtomicAction::Fetch { host } => {
                let kinds = [TokenKind::UrlHost, TokenKind::WordHost];
                probe(seen, host_tokens(host, &kinds))
                    .or_else(|| self.parent_source(atom, host, seen))
            }
            // a word that only looks like a host (`app.run`) is compared with
            // hosts of URLs alone, which prose does not invent, and not with
            // their parents: it is not a request to any of them
            AtomicAction::NetWord { host } => probe(seen, host_tokens(host, &[TokenKind::UrlHost])),
            AtomicAction::FsWrite { path } => probe(
                seen,
                [Token {
                    kind: TokenKind::Path,
                    text: self.path_key(path),
                }],
            ),
            // a command is compared as the classifier reads it, which also
            // yields the command a wrapper runs (`sudo`, `env`, `nohup`,
            // `sh -c`) and leaves `VAR=value` out, at keep and at check alike
            AtomicAction::Shell { argv } => probe(
                seen,
                command_text(argv).map(|text| Token {
                    kind: TokenKind::Command,
                    text,
                }),
            ),
            _ => None,
        }?;
        if self.allows(atom) {
            return None;
        }
        let what = match token.kind {
            TokenKind::UrlHost | TokenKind::WordHost => "host",
            TokenKind::Path => "path",
            TokenKind::Command => "command",
        };
        Some(Found {
            part: format!("the {what} `{}`", token.text),
            source,
        })
    }

    /// The kept URL host a parent domain of `host` matches, and its source:
    /// a kept URL host links a request to any of its subdomains (ADR-063 §4).
    /// One probe per parent, nearest first; a parent the policy allows on its
    /// own (`github.com`) links nothing, so a page naming an allowed site
    /// does not tighten every call to its subdomains. Word hosts are compared
    /// exactly: a name in prose is weaker evidence than a URL (ADR-057 §4).
    fn parent_source(
        &self,
        atom: &AtomicAction,
        host: &str,
        seen: &dyn InjectedLookup,
    ) -> Option<(Token, String)> {
        let host = crate::host::canonical(host);
        crate::host::parents(&host).find_map(|parent| {
            let token = Token {
                kind: TokenKind::UrlHost,
                text: parent.to_owned(),
            };
            let source = seen.source_of(&token)?;
            (!self.allows(&with_host(atom, parent))).then_some((token, source))
        })
    }

    /// Whether the policy decides `atom` `allow` on its own.
    fn allows(&self, atom: &AtomicAction) -> bool {
        self.evaluate_atomic(atom)
            .is_some_and(|d| d.verdict == Verdict::Allow)
    }

    /// The commands `line` runs, as [`Self::with_injected`] compares them.
    fn commands_of(&self, line: &str, ctx: &EvalContext) -> Vec<Token> {
        let action = Action::Shell {
            command: line.to_owned(),
        };
        let (atoms, _) = checked_atoms(&action, ctx, self.opens_as(), &NoResolver);
        atoms
            .iter()
            .filter_map(|atom| match atom {
                AtomicAction::Shell { argv } => command_text(argv),
                _ => None,
            })
            .map(|text| Token {
                kind: TokenKind::Command,
                text,
            })
            .collect()
    }

    /// Whether `path` is the project or below it, under either spelling.
    fn in_project(&self, path: &str) -> bool {
        let key = self.path_key(path);
        [&self.ctx.project, &self.ctx.real_project]
            .into_iter()
            .flatten()
            .any(|root| {
                let root = self.path_key(root);
                let root = root.trim_end_matches('/');
                key == root
                    || key
                        .strip_prefix(root)
                        .is_some_and(|rest| rest.starts_with('/'))
            })
    }

    /// `path` as tokens compare it: lowercase where file names ignore case.
    fn path_key(&self, path: &str) -> String {
        if self.ctx.case_insensitive_paths {
            path.to_lowercase()
        } else {
            path.to_owned()
        }
    }
}

/// The text a command is compared by: its words joined by spaces, when it has
/// arguments and is long enough to be distinctive.
fn command_text(argv: &[String]) -> Option<String> {
    let text = argv.join(" ");
    (argv.len() >= 2 && (MIN_COMMAND_LEN..=MAX_COMMAND_LEN).contains(&text.len())).then_some(text)
}

/// One part of a call that came from untrusted content, worded as the reason
/// names it (the host `x`), and where it came from.
struct Found {
    part: String,
    source: String,
}

/// `decision` with one review per source of `found` merged in, naming each
/// part once: "the command `x`,
/// the host `h` and the path `p` came from …". A planted command makes several
/// atoms (the command, the host it reaches, the file it writes), and the
/// person reads one sentence for them, not one per atom.
fn planted(decision: Decision, found: Vec<Found>) -> Decision {
    let mut sources: Vec<(String, Vec<String>)> = Vec::new();
    for Found { part, source } in found {
        match sources.iter_mut().find(|(known, _)| *known == source) {
            Some((_, parts)) if !parts.contains(&part) => parts.push(part),
            Some(_) => {}
            None => sources.push((source, vec![part])),
        }
    }
    sources
        .into_iter()
        .map(|(source, parts)| {
            Decision::single(
                Verdict::Review,
                injection::INJECTED_RULE,
                format!(
                    "{} came from {source}, untrusted content this session read; the call may \
                     follow an instruction planted there",
                    listed(&parts)
                ),
            )
        })
        .fold(decision, |mut acc, next| {
            acc.merge(next);
            acc
        })
}

/// `a`, `a and b`, `a, b and c`.
fn listed(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The first of `tokens` the session kept, with its source.
fn probe(
    seen: &dyn InjectedLookup,
    tokens: impl IntoIterator<Item = Token>,
) -> Option<(Token, String)> {
    tokens
        .into_iter()
        .find_map(|token| seen.source_of(&token).map(|source| (token, source)))
}

/// The tokens a call's `host` is compared with, one per kind of `kinds`: in
/// its canonical spelling ([`crate::host::canonical`]), which tokens are kept
/// in, then as written (lowercase, no trailing dot) when that differs, which
/// rows kept before ADR-063 hold for an address spelled another way.
fn host_tokens(host: &str, kinds: &[TokenKind]) -> Vec<Token> {
    let canonical = crate::host::canonical(host);
    let written = host.trim_end_matches('.').to_ascii_lowercase();
    let spellings = if written == canonical {
        vec![canonical]
    } else {
        vec![canonical, written]
    };
    spellings
        .iter()
        .flat_map(|text| {
            kinds.iter().map(|kind| Token {
                kind: *kind,
                text: text.clone(),
            })
        })
        .collect()
}

/// `atom`, a `Net` or `Fetch` atom, reaching `host` instead.
fn with_host(atom: &AtomicAction, host: &str) -> AtomicAction {
    let host = host.to_owned();
    if matches!(atom, AtomicAction::Fetch { .. }) {
        AtomicAction::Fetch { host }
    } else {
        AtomicAction::Net { host }
    }
}

/// The host a network atom reaches.
fn host_of(atom: &AtomicAction) -> Option<&str> {
    match atom {
        AtomicAction::Net { host }
        | AtomicAction::Fetch { host }
        | AtomicAction::NetWord { host } => Some(host),
        _ => None,
    }
}

/// The file name of a program word (`/usr/bin/gh` → `gh`).
fn program_name(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

/// `text`, cut to [`MAX_SOURCE_LEN`] characters.
fn cut(text: String) -> String {
    if text.chars().count() <= MAX_SOURCE_LEN {
        return text;
    }
    let mut short: String = text.chars().take(MAX_SOURCE_LEN).collect();
    short.push('…');
    short
}

mod foreign;
#[cfg(test)]
mod tests;

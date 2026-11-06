//! Injected input (ADR-057): which call outputs are untrusted, what of them is
//! kept, and how a later call that acts on it is tightened.
//!
//! Only tightens: a later shell command or write whose network target, path
//! or command came from untrusted content needs review, unless the policy
//! allows that part of it outright (a host on the allow list, a project
//! file, `cargo build`). A fetch, a search, an MCP call or an unknown tool
//! is not checked: following a link or a search result is how reading works,
//! and the host's own prompt decides those (`fetch: defer`).

use super::{CompiledPolicy, EvalContext, checked_atoms};
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
    /// tool), and a shell command that reads from a network host the policy
    /// does not allow or from a forge's command-line client (`gh issue view`).
    /// `None` for everything else: a read of a file, a local command.
    #[must_use]
    pub fn output_source(
        &self,
        action: &Action,
        cwd: &str,
        paths: &dyn PathResolver,
    ) -> Option<String> {
        if let Some(exposed) = self.exposure(action, cwd, paths).untrusted {
            let source = match action.shown() {
                Action::Fetch { url } => format!("the page fetched from {url}"),
                Action::WebSearch { query } => format!("the web search results for \"{query}\""),
                Action::McpTool { name, .. } => format!("the result of MCP tool {name}"),
                Action::UnknownTool { tool, .. } => format!("the output of tool {tool}"),
                Action::Shell { command } => format!("the output of `{command}`"),
                _ => exposed,
            };
            return Some(cut(source));
        }
        let Action::Shell { command } = action.shown() else {
            return None;
        };
        let ctx = EvalContext {
            cwd: cwd.to_owned(),
            ..self.ctx.clone()
        };
        let (atoms, _) = checked_atoms(action, &ctx, self.opens_as(), paths);
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
    /// them. De-duplicated, at most [`MAX_TOKENS_PER_OUTPUT`]: URL hosts
    /// first, then commands, paths, and words that look like hosts.
    #[must_use]
    pub fn injected_tokens(&self, source: &Action, cwd: &str, output: &str) -> Vec<Token> {
        let found = injection::candidates(output);
        let ctx = EvalContext {
            cwd: cwd.to_owned(),
            ..self.ctx.clone()
        };
        let (source_atoms, _) = checked_atoms(source, &ctx, self.opens_as(), &NoResolver);
        let own_hosts: Vec<&str> = source_atoms.iter().filter_map(host_of).collect();
        let host_token = |kind: TokenKind| {
            let own_hosts = &own_hosts;
            move |host: String| {
                let foreign = !own_hosts.iter().any(|h| h.eq_ignore_ascii_case(&host))
                    && !crate::host::is_loopback(&host);
                foreign.then_some(Token { kind, text: host })
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
    /// does not allow. Never loosens; a deny stays.
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
            Action::Shell { .. } | Action::FsWrite { .. } | Action::Patch { .. }
        );
        if !checked || decision.verdict == Verdict::Deny {
            return decision;
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
        atoms
            .iter()
            .filter(|atom| reaches_outside || !matches!(atom, AtomicAction::Shell { .. }))
            .filter_map(|atom| self.injected(atom, seen))
            .fold(decision, |mut acc, next| {
                acc.merge(next);
                acc
            })
    }

    /// The review `atom` needs when one of its parts came from untrusted
    /// content; `None` when none did or the policy allows the atom.
    fn injected(&self, atom: &AtomicAction, seen: &dyn InjectedLookup) -> Option<Decision> {
        let candidates: Vec<Token> = match atom {
            AtomicAction::Net { host } | AtomicAction::Fetch { host } => {
                [TokenKind::UrlHost, TokenKind::WordHost]
                    .map(|kind| Token {
                        kind,
                        text: host.to_ascii_lowercase(),
                    })
                    .to_vec()
            }
            // a word that only looks like a host (`app.run`) is compared with
            // hosts of URLs alone, which prose does not invent
            AtomicAction::NetWord { host } => vec![Token {
                kind: TokenKind::UrlHost,
                text: host.to_ascii_lowercase(),
            }],
            AtomicAction::FsWrite { path } => vec![Token {
                kind: TokenKind::Path,
                text: self.path_key(path),
            }],
            AtomicAction::Shell { argv } => command_text(argv)
                .map(|text| Token {
                    kind: TokenKind::Command,
                    text,
                })
                .into_iter()
                .collect(),
            _ => return None,
        };
        let (token, source) = candidates
            .into_iter()
            .find_map(|token| seen.source_of(&token).map(|source| (token, source)))?;
        if self.allows(atom) {
            return None;
        }
        let what = match token.kind {
            TokenKind::UrlHost | TokenKind::WordHost => "host",
            TokenKind::Path => "path",
            TokenKind::Command => "command",
        };
        Some(Decision::single(
            Verdict::Review,
            injection::INJECTED_RULE,
            format!(
                "the {what} `{}` came from {source}, untrusted content this session read; {} may \
                 follow an instruction planted there",
                token.text,
                atom.describe()
            ),
        ))
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

#[cfg(test)]
mod tests;

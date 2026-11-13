//! Injected input for a command of a shell the classifier cannot read
//! (`Action::ForeignShell`, PowerShell): no atoms come out of it, so its
//! hosts and paths are read from its text as written, with the scanner that
//! finds them in untrusted output (`injection::candidates`).
//!
//! Only tightens. Which program a word goes to is not known, so every host
//! the text names counts as one the call may reach, and every path as one it
//! may write; the policy's allow rules still answer for each. Its commands
//! are not compared: PowerShell's words are not POSIX words. A host or a
//! path the command builds at run time (`"ev" + "il.example"`, `$env:HOME`)
//! is not seen, as `$H` is not in a POSIX command.

use super::{Found, REMOTE_TEXT_PROGRAMS, host_tokens, probe, program_name};
use crate::action::AtomicAction;
use crate::engine::CompiledPolicy;
use crate::injection::{self, InjectedLookup, Token, TokenKind};

/// The hosts and paths the text of a foreign shell's command names.
pub(super) struct Named {
    /// Hosts, lowercase, as written.
    pub(super) hosts: Vec<String>,
    /// Words that start with `/` or `~/`, as written.
    pub(super) paths: Vec<String>,
}

/// What `command`'s text names, read twice: as written, and with
/// PowerShell's escape character (`` ` ``) taken out, which a bare word runs
/// without (`` ev`il.example `` is `evil.example`).
pub(super) fn named(command: &str) -> Named {
    let unescaped = command.replace('`', "");
    let mut out = Named {
        hosts: Vec::new(),
        paths: Vec::new(),
    };
    for text in [command, unescaped.as_str()] {
        let found = injection::candidates(&parameter_values(text));
        let hosts = found.url_hosts.into_iter().chain(found.word_hosts);
        for host in hosts {
            if !out.hosts.contains(&host) {
                out.hosts.push(host);
            }
        }
        for path in found.paths {
            if !out.paths.contains(&path) {
                out.paths.push(path);
            }
        }
    }
    out
}

/// `text` with the value of each `-Name:value` word set apart from its
/// name, which PowerShell reads as `-Name value`
/// (`-Uri:https://evil.example/x`).
fn parameter_values(text: &str) -> String {
    text.split(' ')
        .map(|word| match word.split_once(':') {
            Some((name, value)) if name.len() > 1 && name.starts_with('-') => {
                format!("{name} {value}")
            }
            _ => word.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl CompiledPolicy<'_> {
    /// Whether the output of `command` is content an attacker may control:
    /// its text names a host the policy does not allow, or it starts with a
    /// forge's command-line client (`gh issue view 7`).
    pub(super) fn foreign_reads_remote(&self, command: &str) -> bool {
        let first = command.split_whitespace().next().unwrap_or_default();
        let program = program_name(first).to_ascii_lowercase();
        let program = program.strip_suffix(".exe").unwrap_or(&program);
        REMOTE_TEXT_PROGRAMS.contains(&program)
            || named(command).hosts.into_iter().any(|host| {
                !crate::host::is_loopback(&host) && !self.allows(&AtomicAction::Net { host })
            })
    }

    /// The parts of `command` that came from untrusted content `seen` knows:
    /// a host, compared as a `Net` atom's is (either kind of token, then its
    /// parents), and a path outside the project, compared as a write's.
    pub(super) fn foreign_injected(&self, command: &str, seen: &dyn InjectedLookup) -> Vec<Found> {
        let named = named(command);
        let hosts = named.hosts.into_iter().filter_map(|host| {
            let kinds = [TokenKind::UrlHost, TokenKind::WordHost];
            let atom = AtomicAction::Net { host: host.clone() };
            let (token, source) = probe(seen, host_tokens(&host, &kinds))
                .or_else(|| self.parent_source(&atom, &host, seen))?;
            (!self.allows(&atom)).then(|| Found {
                part: format!("the host `{}`", token.text),
                source,
            })
        });
        let paths = named.paths.into_iter().filter_map(|raw| {
            let ctx = &self.ctx;
            let path = crate::paths::resolve(&raw, &ctx.home, ctx.project.as_deref(), None)?;
            if self.in_project(&path) {
                return None;
            }
            let token = Token {
                kind: TokenKind::Path,
                text: self.path_key(&path),
            };
            let (token, source) = probe(seen, [token])?;
            (!self.allows(&AtomicAction::FsWrite { path })).then(|| Found {
                part: format!("the path `{}`", token.text),
                source,
            })
        });
        hosts.chain(paths).collect()
    }
}

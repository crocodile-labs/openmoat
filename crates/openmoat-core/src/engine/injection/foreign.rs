//! Injected input for a command of a shell the classifier cannot read
//! (`Action::ForeignShell`, PowerShell): no atoms come out of it, so its
//! hosts and paths are read from its text as written, with the scanner that
//! finds them in untrusted output (`injection::candidates`).
//!
//! Only tightens. Which program a word goes to is not known, so every host
//! the text names counts as one the call may reach, and every path as one it
//! may write; the policy's allow rules still answer for each. Its commands
//! are not compared: PowerShell's words are not POSIX words. A host or a
//! path the command builds at run time (`"ev" + "il.example"`, `$env:TEMP`)
//! is not seen, as `$H` is not in a POSIX command.
//!
//! Whether its output is untrusted is read more narrowly, so a local command
//! that merely names a host (`npm install socket.io`) does not turn what it
//! prints into untrusted content: only a URL, the target of a web client and
//! the value of a parameter that names a remote host count, and a forge's
//! client in any of its commands.

use super::{Found, REMOTE_TEXT_PROGRAMS, host_tokens, probe, program_name};
use crate::action::AtomicAction;
use crate::engine::CompiledPolicy;
use crate::injection::{self, InjectedLookup, Token, TokenKind};

/// Programs, and their PowerShell aliases, that fetch what a word after them
/// names.
const WEB_PROGRAMS: [&str; 7] = [
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr",
    "irm",
    "curl",
    "wget",
    "start-bitstransfer",
];

/// Parameters whose value is a remote host or URL, for any command.
const REMOTE_PARAMETERS: [&str; 5] = ["-uri", "-computername", "-smtpserver", "-source", "-proxy"];

/// The hosts and paths the text of a foreign shell's command names.
pub(super) struct Named {
    /// Every host the text names, lowercase, as written.
    pub(super) hosts: Vec<String>,
    /// The hosts it reads from ([`remote_hosts`]).
    pub(super) remote: Vec<String>,
    /// Paths [`injection::candidates`] places (absolute, drive and home).
    pub(super) paths: Vec<String>,
}

/// What `command`'s text names, read twice: as written, and with
/// PowerShell's escape character (`` ` ``) taken out, which a bare word runs
/// without (`` ev`il.example `` is `evil.example`).
pub(super) fn named(command: &str) -> Named {
    let unescaped = command.replace('`', "");
    let mut out = Named {
        hosts: Vec::new(),
        remote: Vec::new(),
        paths: Vec::new(),
    };
    for text in [command, unescaped.as_str()] {
        let text = parameter_values(text);
        let found = injection::candidates(&text);
        let remote = found.url_hosts.iter().cloned().chain(remote_hosts(&text));
        push_new(&mut out.remote, remote);
        push_new(
            &mut out.hosts,
            found.url_hosts.into_iter().chain(found.word_hosts),
        );
        push_new(&mut out.paths, found.paths);
    }
    out
}

/// Add each of `items` that `list` does not hold yet.
fn push_new(list: &mut Vec<String>, items: impl IntoIterator<Item = String>) {
    for item in items {
        if !list.contains(&item) {
            list.push(item);
        }
    }
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

/// The commands of `text`, each as its words without quotes: split where
/// PowerShell may start another command (`;`, `|`, `&&`, `||`, a line, a
/// `( … )`, `{ … }` or `$( … )`), the call operators `&` and `.` taken off.
/// Splitting inside a quoted string only adds commands, which only tightens.
fn segments(text: &str) -> Vec<Vec<String>> {
    text.split(['\n', ';', '|', '(', ')', '{', '}'])
        .flat_map(|part| part.split("&&"))
        .map(|segment| {
            let mut words: Vec<String> = segment
                .split_whitespace()
                .map(|w| w.trim_matches(['\'', '"', ',']).to_owned())
                .filter(|w| !w.is_empty())
                .collect();
            while words
                .first()
                .is_some_and(|w| w == "&" || w == "." || w == "$")
            {
                words.remove(0);
            }
            if let Some(first) = words.first_mut()
                && let Some(rest) = first.strip_prefix('&')
            {
                *first = rest.trim_matches(['\'', '"']).to_owned();
            }
            words
        })
        .filter(|words| !words.is_empty())
        .collect()
}

/// The program a command's first word names: its file name, lowercase,
/// without `.exe` (`C:\tools\gh.exe` is `gh`).
fn program_of(word: &str) -> String {
    let name = program_name(word).to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(&name).to_owned()
}

/// The hosts `text` reads from beyond its URLs: each word after a web client
/// that names a host (`iwr evil.example/x`), and the value of a parameter
/// that names a remote host (`-ComputerName srv.evil.example`).
fn remote_hosts(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for words in segments(text) {
        let web = WEB_PROGRAMS.contains(&program_of(&words[0]).as_str());
        for (i, word) in words.iter().enumerate().skip(1) {
            let after_parameter = REMOTE_PARAMETERS
                .iter()
                .any(|p| words[i - 1].eq_ignore_ascii_case(p));
            if (web && !word.starts_with('-')) || after_parameter {
                hosts.extend(crate::host::of_word(word));
            }
        }
    }
    hosts
}

impl CompiledPolicy<'_> {
    /// Whether the output of `command` is content an attacker may control:
    /// it reads from a host the policy does not allow ([`Named::remote`]), or
    /// one of its commands is a forge's command-line client (`gh issue view
    /// 7`, also after `;`, `|` or `&`).
    pub(super) fn foreign_reads_remote(&self, command: &str) -> bool {
        let forge = segments(&command.replace('`', ""))
            .iter()
            .any(|words| REMOTE_TEXT_PROGRAMS.contains(&program_of(&words[0]).as_str()));
        forge
            || named(command).remote.into_iter().any(|host| {
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

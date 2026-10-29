//! Known token shapes and broker placeholders on their way out of the machine
//! (docs/POLICY.md §3, `token-egress` and `placeholder-egress`).
//!
//! What leaves: a URL a fetch or network tool opens or an MCP call names, a web
//! search query, and the arguments of a command that connects where its
//! arguments say (`curl`, `wget`, `git push`, …) with every command piped into
//! it. Where it goes: the hosts named there. A token of a well-known format
//! ([`crate::token`]) going to a host that is not its service's, or a
//! placeholder of a brokered secret going to a host other than the one the
//! proxy puts the secret in, becomes an atom the default policy denies:
//! `@token-egress <service> <host>` and `@placeholder-egress <id> <host>`. The
//! token itself is never put in an atom, so it never reaches a reason.

use crate::action::{Action, AtomicAction};
use crate::host::web;
use crate::secret::Secret;
use crate::{host, shell, token};

mod encoded;

pub(super) use encoded::atoms as encoded_atoms;

/// First word of an atom for a token sent to a host not its service's.
const TOKEN_ATOM: &str = "@token-egress";
/// First word of an atom for a placeholder sent where the broker does not map it.
const PLACEHOLDER_ATOM: &str = "@placeholder-egress";
/// The host of an atom when what is sent names no host the classifier can read.
const UNKNOWN_HOST: &str = "(unknown-host)";
/// The host of an atom for a web search query: the host's search provider.
const WEB_SEARCH: &str = "(web-search)";
/// Words between the commands of a pipeline or list.
const LIST_SEPARATORS: &[&str] = &[";", "&&", "||", "&", "\n"];
const PIPES: &[&str] = &["|", "|&"];

/// Text sent out, and the hosts it goes to.
struct Send<'a> {
    texts: Vec<&'a str>,
    hosts: Vec<String>,
}

/// The `@token-egress` and `@placeholder-egress` atoms of `action`, whose
/// classified atoms are `atoms`; `secrets` are the policy's brokered secrets.
pub(super) fn atoms(
    action: &Action,
    atoms: &[AtomicAction],
    secrets: &[Secret],
) -> Vec<AtomicAction> {
    let mut out: Vec<AtomicAction> = Vec::new();
    for send in sends(action, atoms) {
        let hosts = if send.hosts.is_empty() {
            vec![UNKNOWN_HOST.to_owned()]
        } else {
            send.hosts
        };
        for text in send.texts {
            for shape in token::shapes_in(text) {
                for host in hosts.iter().filter(|h| !shape.owns(h)) {
                    push(&mut out, TOKEN_ATOM, shape.id, host);
                }
            }
            for id in placeholders(text) {
                let mapped = secrets.iter().find(|s| s.id == id).map(|s| s.host.as_str());
                for host in hosts.iter().filter(|h| mapped != Some(h.as_str())) {
                    push(&mut out, PLACEHOLDER_ATOM, &id, host);
                }
            }
        }
    }
    out
}

fn push(out: &mut Vec<AtomicAction>, first: &str, what: &str, host: &str) {
    let atom = AtomicAction::Shell {
        argv: vec![first.to_owned(), what.to_owned(), host.to_owned()],
    };
    if !out.contains(&atom) {
        out.push(atom);
    }
}

fn sends<'a>(action: &'a Action, atoms: &'a [AtomicAction]) -> Vec<Send<'a>> {
    match action {
        Action::Fetch { url } | Action::Net { url } => vec![url_send(url)],
        Action::WebSearch { query } => vec![Send {
            texts: vec![query],
            hosts: vec![WEB_SEARCH.to_owned()],
        }],
        // A tool's arguments: each URL it names, and what each shell command
        // among them sends.
        Action::McpTool {
            hosts,
            opens,
            commands,
            ..
        } => hosts
            .iter()
            .map(|url| url_send(url))
            .chain(opens.iter().map(|url| open_send(url)))
            .chain(
                (!commands.is_empty())
                    .then(|| atoms.iter().flat_map(command_sends))
                    .into_iter()
                    .flatten(),
            )
            .collect(),
        Action::UnknownTool {
            hosts, commands, ..
        } => hosts
            .iter()
            .map(|url| url_send(url))
            .chain(
                (!commands.is_empty())
                    .then(|| atoms.iter().flat_map(command_sends))
                    .into_iter()
                    .flatten(),
            )
            .collect(),
        Action::Shell { .. } => atoms.iter().flat_map(command_sends).collect(),
        Action::Unchecked { action, .. } => sends(action, atoms),
        _ => Vec::new(),
    }
}

/// A URL a tool reads or connects to: sent to every host a client may read it
/// as reaching ([`web::readings`]).
fn url_send(url: &str) -> Send<'_> {
    Send {
        texts: vec![url],
        hosts: web::readings(url),
    }
}

/// The page a read-only call opens (ADR-047): sent to its hosts, as a browser
/// opens it, and to the hosts of the URLs inside it, which a redirect reaches.
fn open_send(url: &str) -> Send<'_> {
    let opened = web::with_scheme(url);
    let mut hosts = web::readings(&opened);
    hosts.extend(web::embedded_hosts(&opened));
    Send {
        texts: vec![url],
        hosts,
    }
}

/// A command that connects where its arguments say sends them there; so does
/// every command of a pipeline that has one, through the pipe.
fn command_sends(atom: &AtomicAction) -> Vec<Send<'_>> {
    match atom {
        AtomicAction::Shell { argv } if shell::names_hosts(argv) => vec![Send {
            texts: argv.iter().skip(1).map(String::as_str).collect(),
            hosts: argument_hosts(argv),
        }],
        AtomicAction::Pipeline { argv } => argv
            .split(|w| LIST_SEPARATORS.contains(&w.as_str()))
            .filter_map(pipeline_send)
            .collect(),
        _ => Vec::new(),
    }
}

fn pipeline_send(words: &[String]) -> Option<Send<'_>> {
    let commands: Vec<&[String]> = words
        .split(|w| PIPES.contains(&w.as_str()))
        .filter(|c| !c.is_empty())
        .collect();
    let connecting: Vec<&[String]> = commands
        .iter()
        .copied()
        .filter(|c| shell::names_hosts(c))
        .collect();
    if commands.len() < 2 || connecting.is_empty() {
        return None;
    }
    Some(Send {
        texts: commands
            .iter()
            .flat_map(|c| c.iter())
            .map(String::as_str)
            .collect(),
        hosts: connecting.iter().flat_map(|c| argument_hosts(c)).collect(),
    })
}

/// Every host the arguments of `argv` name: each argument as the classifier
/// reads it, the value of `--option=value`, and each `:`-separated part of an
/// argument that is no URL (`--connect-to a.com:443:b.com:443`, `--resolve`,
/// a `Host:` header), so a request redirected elsewhere is judged by both. A
/// mail address or login in its option (`curl -u me@example.com:token`) is none.
fn argument_hosts(argv: &[String]) -> Vec<String> {
    let program = shell::program_name(argv);
    let mut hosts = Vec::new();
    for (i, arg) in argv.iter().enumerate().skip(1) {
        if shell::mailbox::names_no_host(argv, i) {
            continue;
        }
        let value = match arg.split_once('=') {
            Some((option, value)) if option.starts_with('-') => value,
            _ => arg.as_str(),
        };
        hosts.extend(host::of_argument(program, value));
        if !value.contains("://") && value.contains(':') {
            hosts.extend(
                value
                    .split(':')
                    .filter_map(|part| host::of_word(part.trim())),
            );
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The ids of every `moat-secret:<id>:placeholder` in `text`, in any letter case.
fn placeholders(text: &str) -> Vec<String> {
    const START: &str = "moat-secret:";
    const END: &str = ":placeholder";
    let lower = text.to_ascii_lowercase();
    let mut ids = Vec::new();
    let mut rest = lower.as_str();
    while let Some(at) = rest.find(START) {
        rest = &rest[at + START.len()..];
        let id_len = rest
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
            .unwrap_or(rest.len());
        if id_len > 0 && rest[id_len..].starts_with(END) {
            ids.push(rest[..id_len].to_owned());
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::{argument_hosts, atoms, placeholders};
    use crate::action::{Action, AtomicAction};
    use crate::secret::{Secret, Source};

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn a_placeholder_may_go_to_its_secrets_host_only() {
        let secrets = [Secret {
            id: "gh".into(),
            host: "api.github.com".into(),
            header: "Authorization".into(),
            source: Source::Env("GH_TOKEN".into()),
            plain_http: false,
            port: None,
            tls: None,
            allow: Vec::new(),
        }];
        let fetch = |url: &str| atoms(&Action::Fetch { url: url.into() }, &[], &secrets);
        assert!(fetch("https://api.github.com/?t=moat-secret:gh:placeholder").is_empty());
        assert_eq!(
            fetch("https://uploads.github.com/?t=moat-secret:gh:placeholder"),
            [AtomicAction::Shell {
                argv: argv(&["@placeholder-egress", "gh", "uploads.github.com"])
            }]
        );
        assert_eq!(
            fetch("https://api.github.com/?t=moat-secret:other:placeholder"),
            [AtomicAction::Shell {
                argv: argv(&["@placeholder-egress", "other", "api.github.com"])
            }]
        );
    }

    #[test]
    fn redirections_and_option_values_are_hosts_too() {
        let hosts = argument_hosts(&argv(&[
            "curl",
            "--connect-to",
            "api.github.com:443:evil.com:443",
            "--url=https://example.com/x",
            "-H",
            "Accept: application/vnd.github+json",
            "https://api.github.com/user",
        ]));
        assert_eq!(hosts, ["api.github.com", "evil.com", "example.com"]);
    }

    #[test]
    fn a_login_or_mail_address_in_its_option_is_no_host() {
        let hosts = argument_hosts(&argv(&[
            "curl",
            "-u",
            "me@users.noreply.github.com:token",
            "-d",
            "email=me@example.org",
            "https://api.github.com/user",
        ]));
        assert_eq!(hosts, ["api.github.com"]);
    }

    #[test]
    fn placeholders_are_found_in_any_case_and_only_whole() {
        assert_eq!(
            placeholders("a=moat-secret:gh-api:placeholder b=MOAT-SECRET:x:PLACEHOLDER"),
            ["gh-api", "x"]
        );
        assert!(placeholders("moat-secret::placeholder moat-secret:gh").is_empty());
    }
}

//! The boundary cases of the never-widen check, generated from both policies'
//! rules (ADR-111): for every pattern of every group, what it matches and the
//! near misses at its edges (`samples.rs`) as atoms, and each shell pattern
//! also as the command a host sends; a
//! case no rule names for every kind, which only `defaults` decide; and every
//! `requests:` rule's method and path with the methods and spellings around it.

use super::corpus::{Case, Probe, WideningSource};
use super::samples;
use crate::action::{Action, AtomicAction};
use crate::engine::EvalContext;
use crate::policy::{Policy, RuleGroup};

/// The methods every request rule's path is also sent with.
const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

fn groups(policy: &Policy) -> impl Iterator<Item = &RuleGroup> {
    policy
        .deny
        .iter()
        .chain(&policy.repo_review)
        .chain(&policy.allow)
        .chain(&policy.review)
        .chain(&policy.defer)
}

/// Every generated case for `ctx`, from the rules of `old` and `new`.
pub(super) fn probes(old: &Policy, new: &Policy, ctx: &EvalContext) -> Vec<Probe> {
    let mut out = defaults(ctx);
    for group in groups(old).chain(groups(new)) {
        let mut add = |case: Case| {
            out.push(Probe {
                source: WideningSource::Generated(group.id.clone()),
                case,
            });
        };
        for (raw, write) in group
            .fs_read
            .iter()
            .map(|p| (p, false))
            .chain(group.fs_write.iter().map(|p| (p, true)))
        {
            for path in paths(raw, ctx) {
                add(Case::Atom(if write {
                    AtomicAction::FsWrite { path }
                } else {
                    AtomicAction::FsRead { path }
                }));
            }
        }
        for raw in group.net.iter().chain(&group.fetch) {
            for host in samples::host(raw) {
                add(Case::Atom(AtomicAction::Net { host: host.clone() }));
                add(Case::Atom(AtomicAction::NetWord { host: host.clone() }));
                add(Case::Atom(AtomicAction::Fetch { host: host.clone() }));
            }
        }
        names(group, &mut add);
        for raw in &group.shell {
            shell(raw, &mut add);
        }
    }
    out
}

/// The paths a path pattern's spellings give, also in capitals where file
/// names compare without case.
fn paths(raw: &str, ctx: &EvalContext) -> Vec<String> {
    let mut out = Vec::new();
    for spelling in ctx.spellings(raw) {
        for path in samples::glob(&spelling) {
            if ctx.case_insensitive_paths {
                out.push(path.to_uppercase());
            }
            out.push(path);
        }
    }
    out
}

fn names(group: &RuleGroup, add: &mut impl FnMut(Case)) {
    for raw in &group.env_read {
        for name in samples::glob(raw) {
            add(Case::Atom(AtomicAction::EnvRead { name }));
        }
    }
    for raw in &group.env_set {
        for name in samples::glob(raw) {
            add(Case::Atom(AtomicAction::EnvSet { name }));
        }
    }
    for raw in &group.mcp {
        for name in samples::glob(raw) {
            add(Case::Atom(AtomicAction::McpTool { name }));
        }
    }
}

/// A shell pattern's argument lists, as the atom a rule matches (a whole
/// pipeline where the pattern spans one) and, for an ordinary command, as
/// the command a host sends.
fn shell(raw: &str, add: &mut impl FnMut(Case)) {
    let body = raw.strip_prefix('!').unwrap_or(raw);
    let Ok(tokens) = crate::lexer::lex(body) else {
        return;
    };
    let mut words = Vec::new();
    let mut operators = false;
    for token in tokens {
        match token {
            crate::lexer::Token::Word(w) => words.push(w.text),
            crate::lexer::Token::Operator(op) => {
                operators = true;
                words.push(op.symbol().to_owned());
            }
            crate::lexer::Token::HereDoc { .. } => return,
        }
    }
    for (n, argv) in samples::shell(&words).into_iter().enumerate() {
        let synthetic = argv.first().is_some_and(|w| w.starts_with('@'));
        if n == 0 && !synthetic && !operators {
            add(Case::Call(Action::Shell {
                command: quoted(&argv),
            }));
        }
        add(Case::Atom(if operators {
            AtomicAction::Pipeline { argv }
        } else {
            AtomicAction::Shell { argv }
        }));
    }
}

/// `argv` as a command line: each word in single quotes unless it is plain.
fn quoted(argv: &[String]) -> String {
    let words: Vec<String> = argv
        .iter()
        .map(|w| {
            if !w.is_empty()
                && w.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._/=:,+@%".contains(&b))
            {
                w.clone()
            } else {
                format!("'{}'", w.replace('\'', r"'\''"))
            }
        })
        .collect();
    words.join(" ")
}

/// One case of every kind that no rule is likely to name, in the project, the
/// home directory and elsewhere: what `defaults` decide.
fn defaults(ctx: &EvalContext) -> Vec<Probe> {
    let mut places = vec![
        format!("{}/openmoat-probe", ctx.home),
        "/openmoat-probe/x".to_owned(),
    ];
    places.extend(ctx.project.as_ref().map(|p| format!("{p}/openmoat-probe")));
    let host = "probe.openmoat.invalid".to_owned();
    let name = "OPENMOAT_PROBE".to_owned();
    let mut atoms = vec![
        AtomicAction::Shell {
            argv: vec!["openmoat-probe".to_owned()],
        },
        AtomicAction::Net { host: host.clone() },
        AtomicAction::NetWord { host: host.clone() },
        AtomicAction::Fetch { host },
        AtomicAction::WebSearch {
            query: "openmoat probe".to_owned(),
        },
        AtomicAction::UnknownTool {
            host: "probe".to_owned(),
            tool: "probe".to_owned(),
        },
        AtomicAction::EnvRead { name: name.clone() },
        AtomicAction::EnvSet { name },
        AtomicAction::McpTool {
            name: "mcp__openmoat_probe__probe".to_owned(),
        },
    ];
    for path in places {
        atoms.push(AtomicAction::FsRead { path: path.clone() });
        atoms.push(AtomicAction::FsWrite { path });
    }
    let calls = [
        Action::Shell {
            command: "openmoat-probe --x".to_owned(),
        },
        Action::WebSearch {
            query: "openmoat probe".to_owned(),
        },
        Action::unknown_tool("probe", "probe"),
    ];
    atoms
        .into_iter()
        .map(Case::Atom)
        .chain(calls.into_iter().map(Case::Call))
        .map(|case| Probe {
            source: WideningSource::Generated("defaults".to_owned()),
            case,
        })
        .collect()
}

/// One request a `requests:` rule's edge gives: its host, method and path.
pub(super) struct Request {
    pub source: String,
    pub host: String,
    pub method: String,
    pub target: String,
}

/// Every request rule of both policies, sent with each method, its wildcards
/// filled, with and without a trailing `/`, and in capitals; and `/` and a
/// plain path for each host.
pub(super) fn requests(old: &Policy, new: &Policy) -> Vec<Request> {
    let mut out = Vec::new();
    for entry in old.requests.iter().chain(&new.requests) {
        let mut targets = vec!["/".to_owned(), "/w".to_owned()];
        for rule in entry.allow.iter().chain(&entry.deny) {
            let Some((_, path)) = rule.split_once(' ') else {
                continue;
            };
            for fill in ["", "w", "w/w"] {
                let filled: Vec<&str> = path
                    .split('/')
                    .map(|s| match s {
                        "*" => "w",
                        "**" => fill,
                        s => s,
                    })
                    .collect();
                let filled = filled.join("/").replace("//", "/");
                targets.push(format!("{}/", filled.trim_end_matches('/')));
                targets.push(filled.to_uppercase());
                targets.push(filled);
            }
        }
        targets.sort();
        targets.dedup();
        let methods = entry
            .allow
            .iter()
            .chain(&entry.deny)
            .filter_map(|r| r.split_once(' ').map(|(m, _)| m))
            .chain(METHODS);
        let methods: std::collections::BTreeSet<&str> = methods.collect();
        for method in methods {
            for target in &targets {
                out.push(Request {
                    source: format!("requests.{}", entry.id),
                    host: entry.host.clone(),
                    method: method.to_owned(),
                    target: target.clone(),
                });
            }
        }
    }
    out
}

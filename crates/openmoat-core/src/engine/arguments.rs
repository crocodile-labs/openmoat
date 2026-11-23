//! `when:` conditions (ADR-113, docs/POLICY.md §2.4): a `deny` or `review`
//! group that names argument conditions matches a call when one of its
//! patterns matches one of the call's atoms and every condition holds over
//! the call's arguments. Deterministic: globs over values the caller passed
//! and the action names, and the session's injected-input lookup for
//! `provenance`. Such a group never matches an atom on its own
//! ([`super::CompiledGroup::matches`]), so a call is decided as before and
//! [`CompiledPolicy::with_arguments`] can only add its deny or review.

use super::{CompiledPolicy, EvalContext};
use crate::action::{Action, AtomicAction};
use crate::arguments::Arguments;
use crate::injection::{InjectedLookup, Token, TokenKind};
use crate::pattern::{GlobPattern, any_match};
use crate::policy::PolicyError;
use crate::predicate::{Predicate, Test};
use crate::realpath::PathResolver;
use crate::verdict::{Decision, Verdict};

/// The longest value a reason shows.
const SHOWN_CHARS: usize = 80;

/// One group's conditions, compiled for one context.
#[derive(Debug)]
pub(super) struct CompiledWhen {
    conditions: Vec<Condition>,
}

#[derive(Debug)]
struct Condition {
    /// The argument names read; `None` for the test's default.
    names: Option<Vec<String>>,
    test: Test,
    negated: bool,
    patterns: Vec<GlobPattern>,
    /// The condition as written, for reasons.
    shown: String,
}

impl CompiledWhen {
    /// `when` compiled for `ctx`; `None` when it is empty.
    pub(super) fn compile(
        when: &[Predicate],
        ctx: &EvalContext,
    ) -> Result<Option<Self>, PolicyError> {
        if when.is_empty() {
            return Ok(None);
        }
        let conditions = when
            .iter()
            .filter_map(|p| p.test().map(|t| (p, t)))
            .map(|(predicate, (test, negated, list))| {
                let compile = |p: &str, ci: bool| GlobPattern::compile(p, ci);
                let patterns = match test {
                    Test::Under => list
                        .iter()
                        .flat_map(|p| ctx.spellings(p))
                        .flat_map(|p| {
                            let root = p.trim_end_matches('/').to_owned();
                            [format!("{root}/**"), root]
                        })
                        .map(|p| compile(&p, ctx.case_insensitive_paths))
                        .collect::<Result<Vec<_>, _>>()?,
                    Test::HostIn | Test::In => list
                        .iter()
                        .map(|p| compile(p, true))
                        .collect::<Result<Vec<_>, _>>()?,
                    Test::Matches => list
                        .iter()
                        .map(|p| compile(p, false))
                        .collect::<Result<Vec<_>, _>>()?,
                    Test::Untrusted => Vec::new(),
                };
                Ok(Condition {
                    names: predicate
                        .arg
                        .as_ref()
                        .map(|a| a.names().into_iter().map(str::to_owned).collect()),
                    test,
                    negated,
                    patterns,
                    shown: predicate.describe(),
                })
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;
        Ok(Some(Self { conditions }))
    }
}

/// What a condition is checked against: one call.
struct Call<'a> {
    policy: &'a CompiledPolicy<'a>,
    atoms: &'a [AtomicAction],
    args: &'a Arguments,
    seen: &'a dyn InjectedLookup,
}

impl CompiledPolicy<'_> {
    /// `decision` for `action`, with the deny or review of each `deny` and
    /// `review` group whose patterns match one of the call's atoms and whose
    /// `when` conditions all hold. `args` are the call's arguments as the host
    /// sent them (an MCP tool's), flattened by the caller; the action's own
    /// path, URL, command or query are added to them. `seen` answers
    /// `provenance: untrusted`. Merging keeps the strictest verdict, so this
    /// never loosens a decision.
    #[must_use]
    pub fn with_arguments(
        &self,
        decision: Decision,
        action: &Action,
        paths: &dyn PathResolver,
        args: &Arguments,
        seen: &dyn InjectedLookup,
    ) -> Decision {
        let lists = [
            (&self.deny, Verdict::Deny),
            (&self.repo_review, Verdict::Review),
            (&self.review, Verdict::Review),
        ];
        let conditional = lists
            .iter()
            .any(|(groups, _)| groups.iter().any(|g| g.when.is_some()));
        if !conditional {
            return decision;
        }
        let (atoms, _) = self.all_atoms(action, paths);
        let mut all = derived(action);
        all.extend(args);
        let call = Call {
            policy: self,
            atoms: &atoms,
            args: &all,
            seen,
        };
        let mut out = decision;
        for (groups, verdict) in lists {
            for group in groups {
                let Some(when) = &group.when else {
                    continue;
                };
                if !atoms.iter().any(|atom| group.matches_patterns(atom)) {
                    continue;
                }
                let Some(witness) = when.holds(&call) else {
                    continue;
                };
                let why = group
                    .reason
                    .as_ref()
                    .map_or_else(|| witness.clone(), |r| format!("{r}: {witness}"));
                out.merge(Decision::single(verdict, &group.id, why));
            }
        }
        out
    }
}

impl CompiledWhen {
    /// What made every condition hold, joined; `None` when one does not.
    fn holds(&self, call: &Call<'_>) -> Option<String> {
        let witnesses: Option<Vec<String>> =
            self.conditions.iter().map(|c| c.holds(call)).collect();
        witnesses.map(|w| w.join("; "))
    }
}

impl Condition {
    /// What made the condition hold, or `None` when it does not.
    fn holds(&self, call: &Call<'_>) -> Option<String> {
        let values = self.values(call);
        if !self.negated {
            return values
                .iter()
                .find(|(_, v)| self.passes(call, v))
                .map(|(k, v)| format!("{k} {} is {}", shown(v), self.shown));
        }
        if values.is_empty() {
            return Some(format!("the call names no value for {}", self.shown));
        }
        if call.args.is_cut() {
            return Some(format!(
                "not every argument was read, so {} cannot be ruled out",
                self.shown
            ));
        }
        values
            .iter()
            .find(|(_, v)| !self.passes(call, v))
            .map(|(k, v)| format!("{k} {} is {}", shown(v), self.shown))
    }

    /// The values the test reads, each with a label (`` `to` ``), in the form
    /// it compares them: a path normalised, a host lowercase, each address of
    /// a recipient list.
    fn values(&self, call: &Call<'_>) -> Vec<(String, String)> {
        let ctx = &call.policy.ctx;
        let Some(names) = &self.names else {
            return match self.test {
                Test::Under => atom_values(call.atoms, |atom| match atom {
                    AtomicAction::FsRead { path } | AtomicAction::FsWrite { path } => {
                        Some(path.as_str())
                    }
                    _ => None,
                }),
                Test::HostIn => atom_values(call.atoms, |atom| match atom {
                    AtomicAction::Net { host } | AtomicAction::Fetch { host } => Some(host),
                    _ => None,
                }),
                _ => self.read_args(call, &["*".to_owned()], ctx),
            };
        };
        self.read_args(call, names, ctx)
    }

    fn read_args(
        &self,
        call: &Call<'_>,
        names: &[String],
        ctx: &EvalContext,
    ) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (key, value) in call.args.values_of(names) {
            let label = format!("`{key}`");
            match self.test {
                Test::Under => {
                    let path = crate::host::file_url_path(value).unwrap_or_else(|| {
                        crate::paths::normalise(value, &ctx.home, ctx.project.as_deref(), &ctx.cwd)
                    });
                    out.push((label, path));
                }
                Test::HostIn => {
                    let host = if value.contains("://") {
                        crate::host::of_url(value)
                    } else {
                        crate::host::of_word(value)
                    };
                    let host = host.map_or_else(
                        || value.trim().to_ascii_lowercase(),
                        |h| crate::host::canonical(&h),
                    );
                    out.push((label, host));
                }
                Test::In => out.extend(addresses(value).map(|a| (label.clone(), a))),
                Test::Matches | Test::Untrusted => out.push((label, value.to_owned())),
            }
        }
        out
    }

    /// Whether `value` passes the positive form of the test.
    fn passes(&self, call: &Call<'_>, value: &str) -> bool {
        match self.test {
            Test::Untrusted => untrusted(call, value),
            Test::HostIn => any_match(&self.patterns, crate::host::canonical(value).as_str()),
            _ => any_match(&self.patterns, value),
        }
    }
}

/// The values `pick` takes from `atoms`, labelled by the atom.
fn atom_values<'a>(
    atoms: &'a [AtomicAction],
    pick: impl Fn(&'a AtomicAction) -> Option<&'a str>,
) -> Vec<(String, String)> {
    atoms
        .iter()
        .filter_map(|atom| pick(atom).map(|v| (atom.kind().as_str().to_owned(), v.to_owned())))
        .collect()
}

/// The addresses of a recipient value: split at `,` and `;`, the part inside
/// `<…>` when there is one (`Ann <ann@example.com>`), trimmed and lowercase.
fn addresses(value: &str) -> impl Iterator<Item = String> + '_ {
    value.split([',', ';']).filter_map(|part| {
        let part = part.trim();
        let inner = match (part.find('<'), part.rfind('>')) {
            (Some(open), Some(close)) if open < close => &part[open + 1..close],
            _ => part,
        };
        let address = inner.trim().to_lowercase();
        (!address.is_empty()).then_some(address)
    })
}

/// Whether a host or path in `value` came from untrusted output the session
/// read, compared as injected input compares them (ADR-057, ADR-063 §4).
fn untrusted(call: &Call<'_>, value: &str) -> bool {
    let found = crate::injection::candidates(value);
    let ctx = &call.policy.ctx;
    let hosts = found
        .url_hosts
        .iter()
        .chain(&found.word_hosts)
        .flat_map(|h| super::injection::host_tokens(h, &[TokenKind::UrlHost, TokenKind::WordHost]));
    let paths = found.paths.iter().filter_map(|raw| {
        let path = crate::paths::resolve(raw, &ctx.home, ctx.project.as_deref(), Some(&ctx.cwd))?;
        Some(Token {
            kind: TokenKind::Path,
            text: call.policy.path_key(&path),
        })
    });
    hosts
        .chain(paths)
        .any(|token| call.seen.source_of(&token).is_some())
}

/// `value` as a reason shows it: at most [`SHOWN_CHARS`] characters, quoted.
fn shown(value: &str) -> String {
    let mut text: String = value.chars().take(SHOWN_CHARS).collect();
    if value.chars().count() > SHOWN_CHARS {
        text.push('…');
    }
    format!("`{text}`")
}

/// What `action` names itself, as arguments: a host tool's path, URL,
/// command or query, and the paths, URLs and commands an adapter found in a
/// tool's arguments.
fn derived(action: &Action) -> Arguments {
    let mut out = Arguments::new();
    let mut all = |key: &str, values: &[String]| {
        for value in values {
            out.push(&[key], value);
        }
    };
    match action {
        Action::Shell { command } | Action::ForeignShell { command, .. } => {
            all("command", std::slice::from_ref(command));
        }
        Action::FsRead { path } | Action::FsWrite { path } => {
            all("path", std::slice::from_ref(path));
        }
        Action::Net { url } | Action::Fetch { url } => all("url", std::slice::from_ref(url)),
        Action::WebSearch { query } => all("query", std::slice::from_ref(query)),
        Action::Patch { writes } => all("path", writes),
        Action::ReadFiles { paths } => all("path", paths),
        Action::McpTool {
            reads,
            writes,
            hosts,
            opens,
            commands,
            ..
        } => {
            all("path", reads);
            all("path", writes);
            all("url", hosts);
            all("url", opens);
            all("command", commands);
        }
        Action::UnknownTool {
            reads,
            writes,
            hosts,
            commands,
            ..
        } => {
            all("path", reads);
            all("path", writes);
            all("url", hosts);
            all("command", commands);
        }
        Action::Unchecked { action, .. } => return derived(action),
    }
    out
}

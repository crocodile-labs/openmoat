//! The lethal trifecta (ADR-113): a session that read private data and
//! content someone else may have written, then makes a call that can send data
//! out. Each part is ordinary on its own; together they are how an injected
//! instruction carries private data away, even to a host the policy allows.
//!
//! The facts are kept on the session's [`Taint`] (no second store):
//! `private_data_read` is [`Taint::secrets`] or [`Taint::private`],
//! `untrusted_seen` is [`Taint::untrusted`] or [`Taint::seen`], both folded by
//! the caller from the calls that ran ([`CompiledPolicy::exposure`]). The third
//! part is this call: [`CompiledPolicy::egress_targets`]. A session that never
//! read private data is never touched.

use super::{CompiledPolicy, Taint};
use crate::action::{Action, AtomicAction};
use crate::pattern::any_match;
use crate::realpath::PathResolver;
use crate::repo::REPO_RULE_PREFIX;
use crate::rule_id;
use crate::verdict::{Decision, Verdict};
use crate::{host, shell};

/// Rule groups whose matches read private data, wherever the policy puts
/// them: credentials of the agents, the build tools and Kerberos, decoy keys,
/// the whole environment and secret variables, and the commands that print a
/// stored token (`secrets-paths`' shell patterns; its reads are secret
/// material already, [`Taint::secrets`]).
const PRIVATE_RULES: &[&str] = &[
    rule_id::SECRETS_PATHS,
    rule_id::AGENT_CREDENTIALS,
    rule_id::BUILD_CREDENTIALS,
    rule_id::KERBEROS_TICKETS,
    rule_id::CANARY,
    rule_id::ENV_DUMP,
    rule_id::ENV_SECRETS,
];

/// Commands that publish what they are given, by program and the words that
/// follow it: `git push` and its kin send data to a host their arguments may
/// not name. A command that only reads (`gh pr view`) is not one.
const PUBLISHERS: &[(&str, &[&str])] = &[
    ("git", &["push", "send-email"]),
    (
        "gh",
        &[
            "gist create",
            "gist edit",
            "pr create",
            "pr comment",
            "pr edit",
            "issue create",
            "issue comment",
            "issue edit",
            "release create",
            "release upload",
            "api",
            "repo create",
        ],
    ),
    (
        "glab",
        &[
            "mr create",
            "mr note",
            "issue create",
            "issue note",
            "release create",
            "api",
            "snippet create",
        ],
    ),
    ("npm", &["publish"]),
    ("pnpm", &["publish"]),
    ("yarn", &["publish", "npm publish"]),
    ("bun", &["publish"]),
    ("cargo", &["publish"]),
    ("twine", &["upload"]),
    ("gem", &["push"]),
    ("docker", &["push"]),
    ("podman", &["push"]),
    ("poetry", &["publish"]),
    ("uv", &["publish"]),
];

/// The kind of place a call can send data to (ADR-113 §1), as the data-flow
/// atoms name it (ADR-126).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EgressSink {
    /// A connection to or fetch from a host off this machine.
    Network,
    /// A web search: the query leaves.
    WebSearch,
    /// A command that publishes (`git push`, `npm publish`).
    Publish,
    /// An MCP tool that acts (`mcp:<server>`).
    McpSend,
}

impl EgressSink {
    /// The word the data-flow atom carries.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::WebSearch => "web-search",
            Self::Publish => "publish",
            Self::McpSend => "mcp-send",
        }
    }
}

/// Words in an MCP tool's name that make it act rather than read (ADR-061).
pub(super) const ACTING: &[&str] = &[
    "send", "post", "upload", "create", "write", "put", "publish", "share", "comment", "message",
];

impl CompiledPolicy<'_> {
    /// The first private data `atoms` read that is not secret material
    /// ([`Taint::secrets`]): a match of a [`PRIVATE_RULES`] group, a read of a
    /// path `taint.private_paths` names, or a read of a folder that holds such
    /// a group's paths (`tar czf x ~/.ssh`).
    pub(super) fn private_read(&self, atoms: &[AtomicAction]) -> Option<String> {
        atoms.iter().find_map(|atom| {
            let private = match atom {
                AtomicAction::FsRead { path } => {
                    (!self.names_secret(atom) && self.names_private(atom))
                        || any_match(&self.private, path.as_str())
                        || self
                            .folders
                            .rules_held(atom)
                            .iter()
                            .any(|rule| is_private_rule(rule))
                }
                AtomicAction::Shell { .. } | AtomicAction::EnvRead { .. } => {
                    self.names_private(atom)
                }
                _ => false,
            };
            private.then(|| atom.describe())
        })
    }

    /// Whether a [`PRIVATE_RULES`] group of any list matches `atom`.
    fn names_private(&self, atom: &AtomicAction) -> bool {
        [&self.deny, &self.repo_review, &self.allow, &self.review]
            .into_iter()
            .flatten()
            .any(|g| is_private_rule(&g.id) && g.matches(atom))
    }

    /// Where `action`, whose atoms are `atoms`, can send data: each host off
    /// this machine it connects to or fetches from, a web search (the query
    /// leaves), an MCP tool that acts (`mcp:<server>`), and a command that
    /// publishes (`git-push`, `npm-publish`). Each once, in the order found.
    pub(super) fn egress_targets(&self, action: &Action, atoms: &[AtomicAction]) -> Vec<String> {
        self.egress_sinks(action, atoms)
            .into_iter()
            .map(|(_, target)| target)
            .collect()
    }

    /// [`Self::egress_targets`] with the kind of sink each target is, for the
    /// data-flow atoms (ADR-126).
    pub(super) fn egress_sinks(
        &self,
        action: &Action,
        atoms: &[AtomicAction],
    ) -> Vec<(EgressSink, String)> {
        let mut out: Vec<(EgressSink, String)> = Vec::new();
        let mut add = |sink: EgressSink, target: String| {
            if !out.iter().any(|(_, t)| *t == target) {
                out.push((sink, target));
            }
        };
        for atom in atoms {
            match atom {
                AtomicAction::Net { host } | AtomicAction::Fetch { host }
                    if !host::is_loopback(host) =>
                {
                    add(EgressSink::Network, host.clone());
                }
                AtomicAction::WebSearch { .. } => {
                    add(EgressSink::WebSearch, "web-search".to_owned());
                }
                AtomicAction::Shell { argv } => {
                    if let Some(publish) = publishes(argv) {
                        add(EgressSink::Publish, publish);
                    }
                }
                _ => {}
            }
        }
        for push in self.pushes(action) {
            let words: Vec<&str> = push.argv.iter().take(2).map(String::as_str).collect();
            add(EgressSink::Publish, words.join("-"));
        }
        if let Action::McpTool {
            name,
            writes,
            hosts,
            ..
        } = action.shown()
        {
            let tool = name
                .rsplit("__")
                .next()
                .unwrap_or(name)
                .to_ascii_lowercase();
            if !writes.is_empty() || !hosts.is_empty() || ACTING.iter().any(|w| tool.contains(w)) {
                let server = name.split("__").nth(1).unwrap_or(name);
                add(EgressSink::McpSend, format!("mcp:{server}"));
            }
        }
        out
    }

    /// `decision` for `action`, tightened when the session read private data
    /// (`taint.secrets`, `taint.private`) and untrusted content
    /// (`taint.untrusted`, `taint.seen`) and this call can send data out:
    /// `review` by default, `deny` under `taint: { trifecta: deny }`, rule
    /// `lethal-trifecta`, with a reason naming the three parts. A secret with
    /// its own host (a brokered one) going to that host alone is no part.
    /// Merging keeps the strictest verdict, so this never loosens a decision.
    /// Once a glob did not build, the `kernel-error` deny (`engine/unbuilt.rs`).
    #[must_use]
    pub fn with_trifecta(
        &self,
        decision: Decision,
        action: &Action,
        paths: &dyn PathResolver,
        taint: &Taint,
    ) -> Decision {
        self.checked(self.trifecta_of(decision, action, paths, taint))
    }

    fn trifecta_of(
        &self,
        decision: Decision,
        action: &Action,
        paths: &dyn PathResolver,
        taint: &Taint,
    ) -> Decision {
        let untrusted = taint.untrusted.as_ref().or(taint.seen.as_ref());
        let private_read = !taint.secrets.is_empty() || taint.private.is_some();
        let (Some(untrusted), true) = (untrusted, private_read) else {
            return decision;
        };
        if decision.verdict == Verdict::Deny {
            return decision;
        }
        let (atoms, _) = self.atoms(action, paths);
        let targets: Vec<String> = self
            .egress_targets(action, &atoms)
            .into_iter()
            .filter(|target| taint.private.is_some() || !owned_by_secrets(taint, target))
            .collect();
        if targets.is_empty() {
            return decision;
        }
        let private = taint.private.clone().unwrap_or_else(|| {
            taint
                .secrets
                .iter()
                .find(|s| s.host.is_none())
                .or(taint.secrets.first())
                .map(|s| s.source.clone())
                .unwrap_or_default()
        });
        let verdict = crate::taint::TaintSettings::trifecta_under(self.policy.taint.as_ref());
        // The facts only: the block message's `why` line explains the three
        // together, and a reason longer than the message's limit loses its
        // middle, which is where the untrusted source is named.
        let reason = format!(
            "this session read private data ({private}) and content someone else may have \
             written ({untrusted}), and this call can send data to {}",
            targets.join(", ")
        );
        let mut out = decision;
        out.merge(Decision::single(verdict, rule_id::LETHAL_TRIFECTA, reason));
        out
    }
}

/// Whether every secret of `taint` belongs to `target`, its own host: a
/// brokered secret may go there.
pub(super) fn owned_by_secrets(taint: &Taint, target: &str) -> bool {
    !taint.secrets.is_empty()
        && taint.secrets.iter().all(|s| {
            s.host
                .as_deref()
                .is_some_and(|own| own.eq_ignore_ascii_case(target))
        })
}

/// Whether `id` names one of [`PRIVATE_RULES`], or a repository's copy of one.
fn is_private_rule(id: &str) -> bool {
    let base = id.strip_prefix(REPO_RULE_PREFIX).unwrap_or(id);
    PRIVATE_RULES.contains(&base)
}

/// The publishing command `argv` runs (`npm-publish`, `gh-pr-create`), if it
/// is one: its program and the first words after it that are not options.
fn publishes(argv: &[String]) -> Option<String> {
    let program = shell::program_name(argv);
    let (_, commands) = PUBLISHERS.iter().find(|(p, _)| *p == program)?;
    let words: Vec<&str> = argv
        .iter()
        .skip(1)
        .filter(|w| !w.starts_with('-'))
        .take(2)
        .map(String::as_str)
        .collect();
    commands.iter().find_map(|command| {
        let wanted: Vec<&str> = command.split(' ').collect();
        (words.len() >= wanted.len() && words[..wanted.len()] == wanted[..])
            .then(|| format!("{program}-{}", wanted.join("-")))
    })
}

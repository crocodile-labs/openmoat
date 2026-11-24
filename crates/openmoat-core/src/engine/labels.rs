//! Data labels (ADR-126): where the data a session holds came from, kept by
//! source rather than by text, and the `@data-flow` atoms that let a rule
//! name a source and a sink together.
//!
//! A hook sees tool calls and their outputs, never the model's own values,
//! so it cannot tell which output a later call used. A label therefore says
//! "this session read data from this source", not "this value came from it":
//! once a session holds a label, every later sink of the session carries it,
//! however the model reworded, summarised or re-encoded what it read. That is
//! what exact text (ADR-057's tokens, ADR-061's staged files) cannot follow.
//!
//! The labels are kept on the session's [`Taint`] (no second store,
//! ADR-113): the CLI folds them with the rest of the taint. Rules decide the
//! atoms; a session whose labels no deny or review rule names is untouched.

use serde::{Deserialize, Serialize};

use super::trifecta::owned_by_secrets;
use super::{CompiledPolicy, Taint, UntrustedKind};
use crate::action::{Action, AtomicAction};
use crate::pattern::any_match;
use crate::verdict::{Decision, Verdict};

/// The first word of a data-flow atom: `@data-flow <label> <sink> <target>`,
/// with a fifth word `same-source` when the target is where the data came
/// from (an MCP server's own tool, a brokered secret's own host), or
/// `flow-trusted` when `mcp.flow_trusted` lists either MCP server.
pub const DATA_FLOW_ATOM: &str = "@data-flow";

/// Secret material (`secrets-paths`, a brokered secret).
pub const LABEL_SECRET: &str = "secret";
/// Private data other than secret material (ADR-113).
pub const LABEL_PRIVATE: &str = "private";
/// Any output someone else may have written: what the trifecta's `seen`
/// counts (a forge's issue text, a read from a host the policy does not allow).
pub const LABEL_EXTERNAL: &str = "external";
/// A web page or search result.
pub const LABEL_WEB: &str = "web";
/// A host tool OpenMoat does not know.
pub const LABEL_UNKNOWN_TOOL: &str = "unknown-tool";
/// Untrusted content whose source kind is not known: a file an exposed
/// session wrote (ADR-029), or a fold from before labels were kept.
pub const LABEL_UNTRUSTED: &str = "untrusted";
/// How the label of an MCP server's results starts: `mcp:<server>`.
pub const LABEL_MCP_PREFIX: &str = "mcp:";

/// The sink word of a write to a file that runs or steers later
/// (`taint.protected_writes` and the built-in list).
const SINK_PROTECTED_WRITE: &str = "protected-write";
/// The fifth word of an atom whose target is where its data came from.
const SAME_SOURCE: &str = "same-source";
/// The fifth word of an MCP flow one of whose servers `mcp.flow_trusted`
/// lists (ADR-058): the default rule ends at four words, so it skips the flow,
/// and a person's own rule without `$` still names it.
const FLOW_TRUSTED: &str = "flow-trusted";
/// At most this many labels per session; the first ones are kept, so the
/// first untrusted read always has its label.
const MAX_LABELS: usize = 32;

/// One label a session holds: its name and the first call that brought it in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    /// `secret`, `private`, `external`, `web`, `mcp:<server>`, `unknown-tool`.
    pub name: String,
    /// What brought it in, for reasons (`fetch evil.example`).
    pub source: String,
}

impl Taint {
    /// Add the label `name` brought in by `source`, unless the session holds
    /// it already (first source wins) or holds the most it keeps.
    pub(super) fn add_label(&mut self, name: &str, source: &str) {
        if self.labels.len() < MAX_LABELS && !self.labels.iter().any(|l| l.name == name) {
            self.labels.push(Label {
                name: name.to_owned(),
                source: source.to_owned(),
            });
        }
    }

    /// Every label of the session with its source, the ones its other facts
    /// imply included: a fold from before labels were kept, or untrusted
    /// content the CLI added itself (file provenance), carries secrets or
    /// untrusted reads without a label, and those count as `secret`,
    /// `private`, `untrusted` and `external`, so no source goes unlabelled.
    #[must_use]
    pub fn label_set(&self) -> Vec<Label> {
        let mut out = self.labels.clone();
        let mut implied = |name: &str, source: &str| {
            if !out.iter().any(|l| l.name == name) {
                out.push(Label {
                    name: name.to_owned(),
                    source: source.to_owned(),
                });
            }
        };
        if let Some(secret) = self.secrets.first() {
            implied(LABEL_SECRET, &secret.source);
        }
        if let Some(private) = &self.private {
            implied(LABEL_PRIVATE, private);
        }
        if let Some(untrusted) = &self.untrusted
            && !self.labels.iter().any(|l| l.source == *untrusted)
        {
            implied(LABEL_UNTRUSTED, untrusted);
        }
        if let Some(seen) = &self.seen
            && !self
                .labels
                .iter()
                .any(|l| l.name == LABEL_EXTERNAL && l.source == *seen)
        {
            implied(LABEL_EXTERNAL, seen);
            if self.untrusted.is_none() {
                implied(LABEL_UNTRUSTED, seen);
            }
        }
        out
    }
}

/// The label of untrusted content of `kind` that `atom` read.
pub(super) fn untrusted_label(kind: UntrustedKind, atom: &AtomicAction) -> String {
    match (kind, atom) {
        (UntrustedKind::Web, _) => LABEL_WEB.to_owned(),
        (UntrustedKind::Mcp, AtomicAction::McpTool { name }) => {
            format!("{LABEL_MCP_PREFIX}{}", mcp_server(name))
        }
        (UntrustedKind::UnknownTool, _) => LABEL_UNKNOWN_TOOL.to_owned(),
        _ => LABEL_UNTRUSTED.to_owned(),
    }
}

/// The server of an MCP tool's full name (`mcp__<server>__<tool>`).
fn mcp_server(name: &str) -> &str {
    name.split("__").nth(1).unwrap_or(name)
}

impl CompiledPolicy<'_> {
    /// The decisions of the `@data-flow` atoms of `action`, whose atoms are
    /// `atoms`, in a session holding `taint`'s labels: one atom per label
    /// and per place the call can send data to or file it writes that runs
    /// later. Only deny and review rules decide them (an allow or defer rule
    /// never loosens a flow), so a label no rule names changes nothing.
    pub(super) fn label_flows(
        &self,
        action: &Action,
        atoms: &[AtomicAction],
        taint: &Taint,
    ) -> Vec<Decision> {
        let labels = taint.label_set();
        if labels.is_empty() {
            return Vec::new();
        }
        let mut sinks: Vec<(&str, String)> = self
            .egress_sinks(action, atoms)
            .into_iter()
            .map(|(sink, target)| (sink.as_str(), target))
            .collect();
        for atom in atoms {
            if let AtomicAction::FsWrite { path } = atom
                && any_match(&self.protected, path.as_str())
            {
                sinks.push((SINK_PROTECTED_WRITE, path.as_str().to_owned()));
            }
        }
        let mut out = Vec::new();
        for label in &labels {
            for (sink, target) in &sinks {
                let mut argv = vec![
                    DATA_FLOW_ATOM.to_owned(),
                    label.name.clone(),
                    (*sink).to_owned(),
                    target.clone(),
                ];
                if same_source(&label.name, target, taint) {
                    argv.push(SAME_SOURCE.to_owned());
                } else if self.flow_trusted(&label.name, target) {
                    argv.push(FLOW_TRUSTED.to_owned());
                }
                let Some(hit) = self.flow_rules(&AtomicAction::Shell { argv }) else {
                    continue;
                };
                let detail = format!(
                    "this session holds data from {} ({}), and this call can pass it to {sink} {target}, \
                     however it was reworded",
                    describe(&label.name),
                    label.source
                );
                let mut named = Decision::new(hit.verdict);
                for rule in &hit.rules {
                    named.push(rule, detail.clone());
                }
                out.push(named);
            }
        }
        out
    }

    /// Whether an MCP flow from `label` to `target` has a server the policy's
    /// `mcp.flow_trusted` lists, as source or destination (ADR-058).
    fn flow_trusted(&self, label: &str, target: &str) -> bool {
        let trusted = self.policy.mcp_flow_trusted();
        [label, target].into_iter().any(|word| {
            word.strip_prefix(LABEL_MCP_PREFIX)
                .is_some_and(|server| trusted.iter().any(|t| t == server))
        })
    }

    /// The deny and review groups that name `atom`: the user's allow and
    /// defer lists are not read, so a broad allow (`shell: ["*"]`) cannot
    /// take a flow out of a review rule.
    fn flow_rules(&self, atom: &AtomicAction) -> Option<Decision> {
        Self::hit(&self.deny, Verdict::Deny, atom)
            .or_else(|| Self::hit(&self.repo_review, Verdict::Review, atom))
            .or_else(|| Self::hit(&self.review, Verdict::Review, atom))
    }
}

/// Whether `target` is where the data of `label` came from: an MCP server's
/// own tool, or the host every brokered secret of the session belongs to.
fn same_source(label: &str, target: &str, taint: &Taint) -> bool {
    if label.starts_with(LABEL_MCP_PREFIX) {
        return label == target;
    }
    label == LABEL_SECRET && owned_by_secrets(taint, target)
}

/// How a reason names the source of `label`.
fn describe(label: &str) -> String {
    match label {
        LABEL_SECRET => "secret material".to_owned(),
        LABEL_PRIVATE => "private data".to_owned(),
        LABEL_EXTERNAL => "content someone else may have written".to_owned(),
        LABEL_WEB => "the web".to_owned(),
        LABEL_UNKNOWN_TOOL => "a tool OpenMoat does not know".to_owned(),
        LABEL_UNTRUSTED => "untrusted content".to_owned(),
        other => match other.strip_prefix(LABEL_MCP_PREFIX) {
            Some(server) => format!("MCP server {server}"),
            None => other.to_owned(),
        },
    }
}

//! Session taint (ADR-020): what earlier calls of a session brought into it,
//! and how that tightens later decisions.
//!
//! The caller keeps the session's history (the CLI reads it from the audit
//! log) and folds [`CompiledPolicy::exposure`] over the calls that ran. The
//! resulting [`Taint`] then goes into [`CompiledPolicy::with_taint`], which can
//! only turn an outcome stricter.

use serde::{Deserialize, Serialize};

use super::{CompiledPolicy, EvalContext, checked_atoms};
use crate::action::{Action, AtomicAction};
use crate::pattern::{GlobPattern, any_match};
use crate::policy::{Policy, PolicyError};
use crate::realpath::PathResolver;
use crate::repo::REPO_RULE_PREFIX;
use crate::verdict::{Decision, Verdict};

/// The rule group whose `fs.read` patterns name secret material, wherever the
/// policy puts it. In the default policy it denies, so only a policy that reviews
/// for these reads lets one run and taint the session. A repository policy's
/// group with the same base id (prefixed to `repo:secrets-paths` by
/// `RepoPolicy::merge`) is also taint-significant.
const SECRET_RULE: &str = "secrets-paths";

/// The rule id a decision tightened by session taint carries.
pub const TAINT_RULE: &str = "session-taint";

/// Where secret material in a session came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    /// What brought it in, for reasons (`read /Users/me/.ssh/id_rsa`).
    pub source: String,
    /// The one host the secret belongs to and may still go to. `None` for a
    /// file read: it belongs to no host, so every host needs review. The secrets
    /// broker (ADR-020) raises a `Secret` with its own host when a brokered
    /// value is used, so later requests to other hosts need review.
    pub host: Option<String>,
}

/// What earlier calls of one session exposed it to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Taint {
    /// Secret material the session read, de-duplicated by source.
    pub secrets: Vec<Secret>,
    /// The first untrusted content the session read (`fetch docs.rs`), if any.
    pub untrusted: Option<String>,
}

/// Where untrusted content a session read came from: the one list of what
/// injected input reads (ADR-057) and, less the metadata tools
/// (`taint.metadata_tools`), of what taints a session, which
/// [`CompiledPolicy::exposure`] and the provenance report (ADR-056) both use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UntrustedKind {
    /// A web page or search result (`fetch`, `web search`).
    Web,
    /// The result of an MCP tool.
    Mcp,
    /// The result of a host tool OpenMoat does not know.
    UnknownTool,
    /// A file a session that had read untrusted content wrote (ADR-029).
    File,
}

impl UntrustedKind {
    /// The kind of untrusted content `atom` reads, if it reads any.
    #[must_use]
    pub fn of(atom: &AtomicAction) -> Option<Self> {
        match atom {
            AtomicAction::Fetch { .. } | AtomicAction::WebSearch { .. } => Some(Self::Web),
            AtomicAction::McpTool { .. } => Some(Self::Mcp),
            AtomicAction::UnknownTool { .. } => Some(Self::UnknownTool),
            _ => None,
        }
    }

    /// The spelling notes and reports use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Mcp => "mcp",
            Self::UnknownTool => "unknown-tool",
            Self::File => "file",
        }
    }

    /// How a report names it: "after reading web content".
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Web => "web content",
            Self::Mcp => "an MCP tool result",
            Self::UnknownTool => "an unknown tool's result",
            Self::File => "a file an exposed session wrote",
        }
    }
}

impl Taint {
    /// Add what another call exposed the session to.
    pub fn absorb(&mut self, other: Taint) {
        for secret in other.secrets {
            if !self.secrets.contains(&secret) {
                self.secrets.push(secret);
            }
        }
        if self.untrusted.is_none() {
            self.untrusted = other.untrusted;
        }
    }
}

/// The built-in protected paths and the ones `policy` adds, compiled for `ctx`.
pub(super) fn compile_protected(
    policy: &Policy,
    ctx: &EvalContext,
) -> Result<Vec<GlobPattern>, PolicyError> {
    crate::taint::protected_writes(policy.taint.as_ref())
        .flat_map(|p| ctx.spellings(p))
        .map(|p| GlobPattern::compile(&p, ctx.case_insensitive_paths))
        .collect()
}

impl CompiledPolicy<'_> {
    /// What running `action` in `cwd` exposed its session to: secret material
    /// from a read the `secrets-paths` group names, untrusted content from a
    /// fetch, a web search, an unknown tool or an MCP result, except a
    /// metadata tool's (`taint.metadata_tools`). The caller passes only calls that ran; the parts
    /// of an action that cannot be classified expose nothing they can name.
    #[must_use]
    pub fn exposure(&self, action: &Action, cwd: &str, paths: &dyn PathResolver) -> Taint {
        let ctx = EvalContext {
            cwd: cwd.to_owned(),
            ..self.ctx.clone()
        };
        let (atoms, _) = checked_atoms(action, &ctx, self.opens_as(), paths);
        let mut taint = Taint::default();
        for atom in atoms {
            match atom {
                AtomicAction::FsRead { .. } if self.names_secret(&atom) => {
                    taint.absorb(Taint {
                        secrets: vec![Secret {
                            source: atom.describe(),
                            host: None,
                        }],
                        untrusted: None,
                    });
                }
                _ if self.taints(&atom).is_some() => {
                    taint.untrusted.get_or_insert_with(|| atom.describe());
                }
                _ => {}
            }
        }
        taint
    }

    /// The first untrusted content running `action` in `cwd` read, with what
    /// kind it is: the same atoms [`CompiledPolicy::exposure`] counts, for
    /// reports that say where the content came from (ADR-056).
    #[must_use]
    pub fn untrusted_read(
        &self,
        action: &Action,
        cwd: &str,
        paths: &dyn PathResolver,
    ) -> Option<(UntrustedKind, String)> {
        let ctx = EvalContext {
            cwd: cwd.to_owned(),
            ..self.ctx.clone()
        };
        let (atoms, _) = checked_atoms(action, &ctx, self.opens_as(), paths);
        atoms
            .iter()
            .find_map(|atom| self.taints(atom).map(|kind| (kind, atom.describe())))
    }

    /// The kind of untrusted content `atom` brings into its session, which
    /// then taints it: [`UntrustedKind::of`], except the result of an MCP tool
    /// that returns metadata, not content (a browser's tab list,
    /// `taint.metadata_tools`). Injected input still reads that result
    /// ([`Self::output_source`]): a page sets its own title and URL.
    fn taints(&self, atom: &AtomicAction) -> Option<UntrustedKind> {
        let kind = UntrustedKind::of(atom)?;
        match atom {
            AtomicAction::McpTool { name }
                if crate::taint::is_metadata_tool(self.policy.taint.as_ref(), name) =>
            {
                None
            }
            _ => Some(kind),
        }
    }

    /// `decision` for `action`, tightened by `taint`: after secret material,
    /// network to any host but the secret's own, and every MCP call, web
    /// search and unknown tool (the hosts they reach are unknown), needs review; after untrusted content, a write to
    /// a protected path needs review. Merging keeps the strictest verdict, so this
    /// never loosens a decision.
    #[must_use]
    pub fn with_taint(
        &self,
        decision: Decision,
        action: &Action,
        paths: &dyn PathResolver,
        taint: &Taint,
    ) -> Decision {
        // A clean session tightens nothing; skip classifying (and listing the
        // directories of glob operands) a second time.
        if *taint == Taint::default() {
            return decision;
        }
        // After a secret read, a long encoded value in a URL is what a secret
        // looks like on its way out: `@encoded-egress` atoms, which the policy's
        // rules decide (`encoded-egress` denies them in the default policy).
        let encoded = if taint.secrets.is_empty() {
            Vec::new()
        } else {
            super::egress::encoded_atoms(action.shown(), |host| {
                taint.secrets.iter().all(|s| {
                    s.host
                        .as_deref()
                        .is_some_and(|own| own.eq_ignore_ascii_case(host))
                })
            })
        };
        let encoded = encoded
            .iter()
            .filter_map(|atom| self.matched_rules(atom))
            .filter(|hit| matches!(hit.verdict, Verdict::Deny | Verdict::Review));
        self.atoms(action, paths)
            .0
            .iter()
            .filter_map(|atom| self.tainted(atom, taint))
            .chain(encoded)
            .fold(decision, |mut acc, next| {
                acc.merge(next);
                acc
            })
    }

    fn tainted(&self, atom: &AtomicAction, taint: &Taint) -> Option<Decision> {
        let reason = match atom {
            AtomicAction::Net { host }
            | AtomicAction::NetWord { host }
            | AtomicAction::Fetch { host } => {
                let secret = taint.secrets.iter().find(|s| {
                    !s.host
                        .as_deref()
                        .is_some_and(|own| own.eq_ignore_ascii_case(host))
                })?;
                secret_reason(secret, atom)
            }
            AtomicAction::McpTool { .. }
            | AtomicAction::WebSearch { .. }
            | AtomicAction::UnknownTool { .. } => secret_reason(taint.secrets.first()?, atom),
            AtomicAction::FsWrite { path } if any_match(&self.protected, path.as_str()) => {
                format!(
                    "the session read untrusted content ({}); {} changes what runs or what the agent is told later",
                    taint.untrusted.as_ref()?,
                    atom.describe()
                )
            }
            _ => return None,
        };
        Some(Decision::single(Verdict::Review, TAINT_RULE, reason))
    }

    fn names_secret(&self, atom: &AtomicAction) -> bool {
        // A repository policy's rules are renamed to `repo:<id>` by `RepoPolicy::merge`,
        // so match the base id and the prefixed one; `repo_review` carries the review rules
        // merged in (ADR-022), so iterate it too.
        [&self.deny, &self.repo_review, &self.allow, &self.review]
            .into_iter()
            .flatten()
            .any(|g| {
                let id = g.id.as_str();
                (id == SECRET_RULE
                    || id
                        .strip_prefix(REPO_RULE_PREFIX)
                        .is_some_and(|rest| rest == SECRET_RULE))
                    && g.matches(atom)
            })
    }
}

fn secret_reason(secret: &Secret, atom: &AtomicAction) -> String {
    format!(
        "the session read secret material ({}); {} could carry it out",
        secret.source,
        atom.describe()
    )
}

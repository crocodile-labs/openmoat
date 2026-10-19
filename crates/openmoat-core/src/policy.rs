//! Policy file model, loading and linting (docs/POLICY.md).

use std::collections::{BTreeMap, BTreeSet};

/// Fallback verdicts when no rule matches: one verdict for everything, or a map
/// from action kind (`shell`, `fs.read`, `fs.write`, `net`, `fetch`,
/// `web.search`, `tool.unknown`, `env.read`, `env.set`, `mcp`, or `"*"`) to a verdict; a `fetch`
/// without its own entry takes the `net` one. This is how "outbound network is
/// deny-by-default" is expressed, because deny rules are absolute and cannot
/// be punched through by allow rules (ADR-002).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Defaults {
    /// The same verdict for every kind.
    All(Verdict),
    /// A verdict per kind name (`net`, `fs.read`, …), with `*` as the fallback.
    PerKind(BTreeMap<String, Verdict>),
}

impl Defaults {
    /// Verdict and synthetic rule id (`default` or `default.<kind>`) for a kind.
    #[must_use]
    pub fn for_kind(&self, kind: Kind) -> (Verdict, String) {
        match self {
            Self::All(v) => (*v, "default".to_owned()),
            Self::PerKind(map) => kind
                .rule_kinds()
                .iter()
                .find_map(|k| map.get(k.as_str()).map(|v| (*v, format!("default.{k}"))))
                .unwrap_or_else(|| {
                    (
                        map.get("*").copied().unwrap_or(Verdict::Ask),
                        "default".to_owned(),
                    )
                }),
        }
    }

    /// The default for an atom no rule matched: [`Self::for_kind`], except that a
    /// word that only looks like a host is no network evidence and gets
    /// [`Self::unclassified`] (ADR-025).
    #[must_use]
    pub fn for_atom(&self, atom: &crate::AtomicAction) -> (Verdict, String) {
        match atom {
            crate::AtomicAction::NetWord { .. } => (self.unclassified(), "default".to_owned()),
            _ => self.for_kind(atom.kind()),
        }
    }

    /// What OpenMoat gives a call it cannot classify, or a word that only looks
    /// like a host: `defer` under a catch-all (`"*"`) of `allow` or `defer`, else
    /// `ask` (ADR-025). Never `allow`, and never a deny nothing named.
    #[must_use]
    pub fn unclassified(&self) -> Verdict {
        let catch_all = match self {
            Self::All(v) => *v,
            Self::PerKind(map) => map.get("*").copied().unwrap_or(Verdict::Ask),
        };
        catch_all.clamp(Verdict::Defer, Verdict::Ask)
    }
}

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::kind::Kind;
use crate::pattern::{GlobPattern, ShellPattern};
use crate::secret::{self, Secret};
use crate::taint::{self, TaintSettings};
use crate::verdict::Verdict;

pub const SUPPORTED_VERSION: u32 = 1;

/// Why a policy file cannot be used. Any of these keeps `guard` from deciding.
///
/// Messages include their cause, so no variant also exposes it as `source`:
/// a chained report (`{:#}`) would print it twice.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The file is not valid YAML or does not fit the schema.
    #[error("policy parse error: {0}")]
    Parse(crate::yaml::Error),
    /// The `version` key names a schema this build does not know.
    #[error("unsupported policy version {found}; this build supports {supported}")]
    Version {
        /// The version in the file.
        found: u32,
        /// The version this build supports.
        supported: u32,
    },
    /// Two rule groups share an id.
    #[error("duplicate rule id `{0}`")]
    DuplicateId(String),
    /// A rule group lists no patterns.
    #[error("rule `{0}` has no patterns")]
    EmptyRule(String),
    /// A pattern is empty (or only `!`/`$`).
    #[error("empty pattern")]
    EmptyPattern,
    /// A glob does not compile.
    #[error("bad glob `{pattern}`: {error}")]
    BadGlob {
        /// The pattern as written.
        pattern: String,
        /// The glob compiler's explanation.
        error: globset::Error,
    },
    /// A shell pattern does not tokenise (unbalanced quotes, a here-document).
    #[error("bad shell pattern `{pattern}` (unbalanced quotes?)")]
    BadShellPattern {
        /// The pattern as written.
        pattern: String,
    },
    /// A rule group or `executables` entry is invalid; `problem` says why.
    #[error("rule `{rule}`: {problem}")]
    Rule {
        /// Rule id, or `executables.<name>`.
        rule: String,
        /// What is wrong.
        problem: String,
    },
}

/// One named group of patterns. A group matches when **any** of its patterns
/// matches the atomic action of the corresponding kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleGroup {
    /// Stable identifier shown in decisions and the audit log.
    pub id: String,
    /// Text prepended to the reason when this group decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Shell patterns (token prefixes, `*`, `!`, trailing `$`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shell: Vec<String>,
    /// Path globs for file reads.
    #[serde(default, rename = "fs.read", skip_serializing_if = "Vec::is_empty")]
    pub fs_read: Vec<String>,
    /// Path globs for file writes.
    #[serde(default, rename = "fs.write", skip_serializing_if = "Vec::is_empty")]
    pub fs_write: Vec<String>,
    /// Host globs for any network access, fetches included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net: Vec<String>,
    /// Host globs for read-only fetches by a host's fetch tool only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fetch: Vec<String>,
    /// Variable-name globs for reads.
    #[serde(default, rename = "env.read", skip_serializing_if = "Vec::is_empty")]
    pub env_read: Vec<String>,
    /// Variable-name globs for sets.
    #[serde(default, rename = "env.set", skip_serializing_if = "Vec::is_empty")]
    pub env_set: Vec<String>,
    /// MCP tool-name globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp: Vec<String>,
}

impl RuleGroup {
    /// The patterns this group lists for `kind`.
    #[must_use]
    pub fn patterns(&self, kind: Kind) -> &[String] {
        match kind {
            Kind::Shell => &self.shell,
            Kind::FsRead => &self.fs_read,
            Kind::FsWrite => &self.fs_write,
            Kind::Net => &self.net,
            Kind::Fetch => &self.fetch,
            // A query or an unknown tool names no host or path to match; only
            // `defaults` decide them.
            Kind::WebSearch | Kind::UnknownTool => &[],
            Kind::EnvRead => &self.env_read,
            Kind::EnvSet => &self.env_set,
            Kind::Mcp => &self.mcp,
        }
    }

    fn is_empty(&self) -> bool {
        Kind::ALL.iter().all(|k| self.patterns(*k).is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default = "default_roots")]
    pub project_roots: Vec<String>,
}

fn default_roots() -> Vec<String> {
    vec![".".to_owned()]
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            project_roots: default_roots(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalChannel {
    Terminal,
    Telegram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RememberScope {
    Once,
    Session,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    #[serde(default = "default_channel")]
    pub channel: ApprovalChannel,
    #[serde(default = "default_remember")]
    pub remember: RememberScope,
    #[serde(default = "default_timeout")]
    pub timeout_s: u32,
}

fn default_channel() -> ApprovalChannel {
    ApprovalChannel::Terminal
}
fn default_remember() -> RememberScope {
    RememberScope::Session
}
fn default_timeout() -> u32 {
    300
}

impl Default for Approval {
    fn default() -> Self {
        Self {
            channel: default_channel(),
            remember: default_remember(),
            timeout_s: default_timeout(),
        }
    }
}

/// The policy document (`policy.yaml`), as written by users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Schema version; only 1 is supported.
    pub version: u32,
    /// Verdict when no rule matches.
    #[serde(default = "default_verdict")]
    pub defaults: Defaults,
    /// Reserved for multi-root projects; parsed so existing files stay valid,
    /// not yet consulted (`policy lint` warns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// Evaluated first; a match is final.
    #[serde(default)]
    pub deny: Vec<RuleGroup>,
    /// Evaluated after `deny`.
    #[serde(default)]
    pub allow: Vec<RuleGroup>,
    /// Evaluated after `allow`.
    #[serde(default)]
    pub ask: Vec<RuleGroup>,
    /// Evaluated after `ask`: calls the agent's own permission flow decides
    /// (ADR-025). Absent in policies written before it existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub defer: Vec<RuleGroup>,
    /// Reserved for the kernel's own approval prompt; parsed so existing files
    /// stay valid, not yet consulted (`policy lint` warns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<Approval>,
    /// Basename → allowed absolute paths (defeats PATH poisoning).
    #[serde(default)]
    pub executables: BTreeMap<String, Vec<String>>,
    /// What the operating-system layers OpenMoat configures need beyond the rules
    /// (ADR-018). Absent in policies written before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxSettings>,
    /// Secrets `moat proxy` keeps from the agent and injects for one host each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<Secret>,
    /// What session taint protects beyond the built-in list. Absent in older policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint: Option<TaintSettings>,
    /// Trust a repository policy only when its detached signature
    /// (`policy.yaml.sig`) verifies against a key the person trusted (ADR-031):
    /// a signed one needs no `moat trust`, and an unsigned one is not trusted even
    /// after `moat trust`. Off by default: then only `moat trust` lets a
    /// repository policy allow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_signed_repo_policy: bool,
    /// How `moat mcp proxy` treats tool definitions (ADR-032). Absent in older policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpSettings>,
    /// Ask rules merged in from a repository policy ([`crate::RepoPolicy`],
    /// ADR-022) or a policy pack (ADR-031). Tried after `deny` and before
    /// `allow`, so a repository can make an action the user allows ask. Never
    /// read from or written to a file, and not lowered to OS layers, which are
    /// generated from the user policy alone.
    #[serde(skip)]
    pub repo_ask: Vec<RuleGroup>,
}

/// The `sandbox:` section (ADR-018, ADR-019).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSettings {
    /// Paths (directories or files) the OS layers let commands read although no
    /// allow rule covers them: system and toolchain directories every build
    /// reads. The hook decision ignores them, and deny rules win over them in
    /// every layer. Absolute or `~/…`, never a glob.
    #[serde(default)]
    pub read_roots: Vec<String>,
    /// The loopback port `moat proxy` listens on and the host sandboxes send
    /// their commands' traffic to; absent, the CLI's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<std::num::NonZeroU16>,
    /// Let `moat proxy` forward a TLS `ClientHello` that carries an encrypted
    /// server name (ECH, ESNI). Off, such a tunnel is refused: the server acts
    /// on the encrypted name, which may be another site than the allowed host.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub proxy_allow_ech: bool,
    /// Days a package version must have been published before the package
    /// managers `moat run` starts install it (ADR-030); `0` turns this off,
    /// absent is 7 days ([`Policy::package_min_release_age_days`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_min_release_age_days: Option<u16>,
}

/// The `mcp:` section (ADR-032).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpSettings {
    /// Pin every tool `moat mcp proxy` sees from a server it has no pins for,
    /// as it is, instead of holding them until `moat mcp accept`. Off by
    /// default: a server that is malicious on first contact would get its
    /// tool descriptions pinned as good.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trust_first_sight: bool,
}

/// The release age `moat run` asks of new package versions when the policy
/// does not say (ADR-030).
pub const DEFAULT_PACKAGE_MIN_RELEASE_AGE_DAYS: u16 = 7;

impl Policy {
    /// The days a package version must have been published before `moat run`
    /// lets npm and uv install it; `0` is off.
    #[must_use]
    pub fn package_min_release_age_days(&self) -> u16 {
        self.sandbox
            .as_ref()
            .and_then(|s| s.package_min_release_age_days)
            .unwrap_or(DEFAULT_PACKAGE_MIN_RELEASE_AGE_DAYS)
    }

    /// Whether `moat mcp proxy` pins a new server's tools without a person
    /// accepting them (`mcp.trust_first_sight`, ADR-032).
    #[must_use]
    pub fn trust_mcp_first_sight(&self) -> bool {
        self.mcp.as_ref().is_some_and(|m| m.trust_first_sight)
    }
}

fn default_verdict() -> Defaults {
    Defaults::All(Verdict::Ask)
}

impl Policy {
    /// Parse and lint a policy document. Pure: takes the YAML text.
    pub fn parse(yaml: &str) -> Result<Self, PolicyError> {
        let policy: Self = crate::yaml::from_str(yaml).map_err(PolicyError::Parse)?;
        policy.lint()?;
        Ok(policy)
    }

    /// Structural validation independent of any environment.
    pub fn lint(&self) -> Result<(), PolicyError> {
        if self.version != SUPPORTED_VERSION {
            return Err(PolicyError::Version {
                found: self.version,
                supported: SUPPORTED_VERSION,
            });
        }
        let mut ids = BTreeSet::new();
        let groups = self.deny.iter().chain(&self.repo_ask);
        for group in groups
            .chain(&self.allow)
            .chain(&self.ask)
            .chain(&self.defer)
        {
            if group.id.trim().is_empty() {
                return Err(PolicyError::Rule {
                    rule: "<unnamed>".into(),
                    problem: "missing id".into(),
                });
            }
            if !ids.insert(group.id.clone()) {
                return Err(PolicyError::DuplicateId(group.id.clone()));
            }
            if group.is_empty() {
                return Err(PolicyError::EmptyRule(group.id.clone()));
            }
            for kind in Kind::ALL {
                for p in group.patterns(kind) {
                    let compiled = if kind == Kind::Shell {
                        ShellPattern::compile(p).map(drop)
                    } else {
                        GlobPattern::compile(p, false).map(drop)
                    };
                    compiled.map_err(|e| rule_err(&group.id, &e))?;
                }
            }
        }
        for (name, paths) in &self.executables {
            if paths.is_empty() {
                return Err(PolicyError::Rule {
                    rule: format!("executables.{name}"),
                    problem: "no paths listed".into(),
                });
            }
            if let Some(bad) = paths.iter().find(|p| !crate::paths::is_absolute(p)) {
                return Err(PolicyError::Rule {
                    rule: format!("executables.{name}"),
                    problem: format!("`{bad}` is not an absolute path"),
                });
            }
        }
        for root in self.sandbox.iter().flat_map(|s| &s.read_roots) {
            lint_read_root(root)?;
        }
        taint::check(self.taint.as_ref())?;
        secret::check(&self.secrets)
    }

    /// Number of rule groups in `deny`, `allow` and `ask`.
    #[must_use]
    pub fn rule_count(&self) -> (usize, usize, usize) {
        (self.deny.len(), self.allow.len(), self.ask.len())
    }
}

/// An OS layer takes a read root literally, and a root that is the disk or the
/// home directory would undo every default deny.
fn lint_read_root(root: &str) -> Result<(), PolicyError> {
    let trimmed = root.trim_end_matches(['/', '\\']);
    let problem = if !(crate::paths::is_absolute(root) || root.starts_with("~/")) {
        "must be absolute or start with `~/`"
    } else if root.contains(['*', '?', '[', ']', '{', '}', '!', '$']) {
        "must be a plain path, not a glob or a variable"
    } else if root.split(['/', '\\']).any(|s| s == "." || s == "..") {
        "must not contain `.` or `..` segments"
    } else if trimmed == "~" {
        "must not be the home directory"
    } else if trimmed.is_empty() || (trimmed.len() == 2 && trimmed.ends_with(':')) {
        "must not be a filesystem root"
    } else {
        return Ok(());
    };
    Err(PolicyError::Rule {
        rule: "sandbox.read_roots".to_owned(),
        problem: format!("`{root}` {problem}"),
    })
}

fn rule_err(rule: &str, e: &PolicyError) -> PolicyError {
    PolicyError::Rule {
        rule: rule.to_owned(),
        problem: e.to_string(),
    }
}

#[cfg(test)]
mod tests;

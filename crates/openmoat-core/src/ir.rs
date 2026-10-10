//! The policy compiler's intermediate representation (ADR-019).
//!
//! [`lower()`] derives from `policy.yaml` the part of a decision an operating
//! system layer can enforce: which paths may be read or written and which
//! hosts may be reached. Every OS backend (a host's sandbox settings, Seatbelt,
//! Landlock, the egress proxy) is generated from this one [`Enforcement`]; the
//! hook backend is the engine itself ([`crate::CompiledPolicy`]), compiled from
//! the same policy and context.
//!
//! An OS layer can only allow or deny, so lowering never widens: a hook `ask`
//! becomes a deny, and whatever cannot be represented exactly is narrowed and
//! recorded as a [`Loss`]. The IR's verdict on any read, write or host is
//! therefore the engine's verdict with `ask` read as `deny`, or stricter.

use std::fmt;

use serde::Serialize;

use crate::kind::Kind;

mod check;
mod lower;

pub use check::Checker;
pub use lower::{CLOUD_METADATA, CLOUD_METADATA_RULE, READ_ROOTS_RULE, lower};

/// What an OS layer may enforce for one policy in one context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Enforcement {
    /// File reads and writes.
    pub fs: Filesystem,
    /// Outbound network.
    pub egress: Egress,
    /// Secrets the egress proxy and Claude Code's own broker inject for the
    /// agent (ADR-020). One entry per policy `secrets:` item; OS backends
    /// consume these without reading the policy again.
    pub secrets: Vec<BrokeredSecret>,
    /// Limits on the agent's processes. Always empty: no policy key sets one yet.
    pub limits: Vec<ProcessLimit>,
    /// Rules only the hook can apply, by kind. Shell semantics, environment
    /// variables, MCP tool names and executable pins name things an OS layer
    /// cannot see (a command line, a variable, a tool), so they are not lowered
    /// and stay with the hook decision (ADR-018).
    pub decide_only: Vec<DecideOnly>,
    /// Where the IR is stricter than the hook decision, with the reason.
    pub losses: Vec<Loss>,
    /// Where OS layers may be wider than the hook decision, listed in the
    /// policy (`sandbox.read_roots`). The hook keeps deciding these accesses;
    /// deny rules still win over them. Not part of [`Filesystem`], so the IR's
    /// own verdicts stay the hook's or stricter.
    pub allowances: Vec<Allowance>,
}

/// File access rules. Paths are absolute, slash-separated globs with `~` and
/// `${project}` already expanded once per spelling of each root (the home
/// directory and project as given and with their symlinks resolved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Filesystem {
    /// Whether paths compare case-insensitively (default macOS and Windows file systems).
    pub case_insensitive: bool,
    /// Reads.
    pub read: Access,
    /// Writes, creates, deletes and moves.
    pub write: Access,
}

/// Network rules. Hosts are lowercase globs and always compare case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Egress {
    /// Any connection, a host fetch tool's included.
    pub net: Access,
    /// Requests by a host's read-only fetch tool (`WebFetch`), which `fetch`
    /// and `net` rules both govern (ADR-017).
    pub fetch: Access,
}

/// The rules for one kind of access, applied in order: a matching `deny` rule
/// denies; otherwise a matching `allow` rule allows; otherwise `default`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Access {
    /// The effect when no rule matches.
    pub default: Effect,
    /// Rules that deny; an allow never overrides them.
    pub deny: Vec<Rule>,
    /// Rules that allow.
    pub allow: Vec<Rule>,
}

/// One policy rule group's patterns from one list. It matches when at least
/// one pattern matches and no `!` exclusion does, as in the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    /// The policy rule group's id ([`CLOUD_METADATA_RULE`] for the built-in one).
    pub id: String,
    /// The policy list the patterns come from (`net` patterns also govern `fetch`).
    pub list: Kind,
    /// Expanded globs; a leading `!` excludes.
    pub patterns: Vec<String>,
}

/// What an OS layer does with an access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// The access may proceed.
    Allow,
    /// The access is blocked.
    Deny,
}

/// The policy rules of one kind that only the hook applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecideOnly {
    /// `shell`, `env.read`, `env.set`, `mcp` or `executables`.
    pub kind: String,
    /// Rule group ids, or program names for `executables`.
    pub rules: Vec<String>,
}

/// A place where the IR denies something the hook would not deny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Loss {
    /// The access the loss applies to.
    pub kind: Kind,
    /// The rule group id, or `default.<kind>`/`default` for the defaults table.
    pub rule: String,
    /// What the hook does and what OS layers do instead.
    pub message: String,
}

impl fmt::Display for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} `{}`: {}", self.kind, self.rule, self.message)
    }
}

/// Accesses OS layers allow although the hook would not (ADR-019: the only
/// way an OS layer may be wider than the hook, and always listed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Allowance {
    /// The access the allowance applies to.
    pub kind: Kind,
    /// Where it comes from (`sandbox.read_roots`).
    pub rule: String,
    /// Expanded globs: each root and everything below it.
    pub patterns: Vec<String>,
    /// What the hook does and what OS layers do instead.
    pub message: String,
}

impl fmt::Display for Allowance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} `{}`: {}", self.kind, self.rule, self.message)
    }
}

/// A secret the egress proxy or Claude Code's own broker injects (ADR-020).
/// A copy of [`crate::Secret`]: the IR carries only the fields OS backends
/// need, so a backend can read `ir.secrets` without the policy. Its `Debug`
/// output names only the id, as for [`crate::Secret`].
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BrokeredSecret {
    /// Stable identifier (lowercase letters, digits and `-`).
    pub id: String,
    /// The one host whose requests receive the secret, lowercase DNS or IPv4.
    pub host: String,
    /// The request header the secret goes in (`Authorization`, `X-Api-Key`).
    pub header: String,
    /// Where OpenMoat reads the value.
    pub source: crate::SecretSource,
    /// Also inject into plain-HTTP requests; off unless the policy sets it.
    pub plain_http: bool,
}

impl std::fmt::Debug for BrokeredSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokeredSecret")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A process limit. No value exists until the policy schema defines one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProcessLimit {}

#[cfg(test)]
mod tests;

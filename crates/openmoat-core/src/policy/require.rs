//! The `require:` section (ADR-064): the least protection level an agent must
//! be at for OpenMoat to let any of its calls through. The level itself is
//! worked out by the CLI, which can see the hook and the sandboxes; this
//! module only holds what the policies ask for and which of them asks most.
//!
//! A repository policy and a policy pack can add a requirement, never take one
//! away: [`Policy::required_for`] is the strictest of every source, so a lower
//! level from one of them leaves a higher one from another in force.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Policy, PolicyError};

/// A protection level a policy can require, weakest first, so the derived
/// order is "at least as protected as".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredLevel {
    /// OpenMoat's hook decides the agent's calls (`openmoat status`'s
    /// `hook-only` or better).
    HookOnly,
    /// The hook decides, and an OS sandbox from OpenMoat holds the commands
    /// the agent runs (`hook-and-os-sandbox`): the host's own sandbox as
    /// OpenMoat configured it, or `openmoat run`.
    HookAndOsSandbox,
}

impl RequiredLevel {
    /// The level as `require:` and `openmoat status --format json` spell it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HookOnly => "hook-only",
            Self::HookAndOsSandbox => "hook-and-os-sandbox",
        }
    }
}

/// The `require:` section of a policy, a repository policy or a pack.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Require {
    /// The least level of every agent; absent, none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<RequiredLevel>,
    /// The least level of one agent, by its host id (as `openmoat status` names it), in
    /// place of [`Self::protection`] for that agent in this file. Another
    /// source's higher level still applies ([`Policy::required_for`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, RequiredLevel>,
}

impl Require {
    /// What this section asks of `host` (a host id), or of a program that is
    /// no known agent when `host` is `None`: only [`Self::protection`].
    #[must_use]
    pub fn for_agent(&self, host: Option<&str>) -> Option<RequiredLevel> {
        host.and_then(|h| self.agents.get(h).copied())
            .or(self.protection)
    }

    /// Every host id [`Self::agents`] names, for the CLI to check against the
    /// hosts it knows.
    pub fn agent_ids(&self) -> impl Iterator<Item = &str> {
        self.agents.keys().map(String::as_str)
    }
}

/// Where a requirement in force comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredBy {
    /// The person's own `policy.yaml`.
    Policy,
    /// The project's repository policy (`.moat/policy.yaml`, ADR-022).
    Repository,
    /// The installed policy pack of this name (ADR-031).
    Pack(String),
}

/// The level an agent must be at, and which policy asks for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The least level.
    pub level: RequiredLevel,
    /// The source that asks for it; of two that ask for the same level, the
    /// person's own policy, then the first merged.
    pub by: RequiredBy,
}

impl Policy {
    /// The level `host` (a host id; `None` for a program that is no known
    /// agent) must be at: the strictest that the policy and every repository
    /// policy and pack merged into it ask for, or `None` when none does.
    #[must_use]
    pub fn required_for(&self, host: Option<&str>) -> Option<Requirement> {
        let own = self.require.iter().map(|r| (RequiredBy::Policy, r));
        let added = self.require_added.iter().map(|(by, r)| (by.clone(), r));
        own.chain(added)
            .filter_map(|(by, r)| r.for_agent(host).map(|level| Requirement { level, by }))
            .fold(
                None,
                |strictest: Option<Requirement>, next| match strictest {
                    Some(kept) if kept.level >= next.level => Some(kept),
                    _ => Some(next),
                },
            )
    }

    /// Add the requirement `require` of `by` (a repository policy or a pack)
    /// to the ones [`Self::required_for`] reads. It can only raise a level.
    pub fn add_requirement(&mut self, by: RequiredBy, require: &Require) {
        self.require_added.push((by, require.clone()));
    }
}

/// An agent id must look like a host id; whether a host has it is the CLI's to
/// check, since the core does not know the hosts.
pub(super) fn check(require: Option<&Require>) -> Result<(), PolicyError> {
    for id in require.iter().flat_map(|r| r.agent_ids()) {
        let valid = !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid {
            return Err(PolicyError::Rule {
                rule: "require.agents".to_owned(),
                problem: format!(
                    "`{id}` is not an agent id (lowercase letters, digits and `-`, as `openmoat status` names agents)"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

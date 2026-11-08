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
    /// The least level of one agent, by its host id (`codex`, `cursor`), in
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
                problem: format!("`{id}` is not an agent id (`claude-code`, `codex`, …)"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RepoPolicy;

    const USER: &str = "version: 1\nrequire:\n  protection: hook-and-os-sandbox\n  \
        agents:\n    gemini-cli: hook-only\n";

    fn level(p: &Policy, host: Option<&str>) -> Option<RequiredLevel> {
        p.required_for(host).map(|r| r.level)
    }

    #[test]
    fn levels_order_from_weakest_to_strongest() {
        assert!(RequiredLevel::HookOnly < RequiredLevel::HookAndOsSandbox);
        assert_eq!(
            RequiredLevel::HookAndOsSandbox.as_str(),
            "hook-and-os-sandbox"
        );
        assert_eq!(RequiredLevel::HookOnly.as_str(), "hook-only");
    }

    #[test]
    fn absent_means_no_requirement() {
        let p = Policy::parse("version: 1\n").unwrap();
        assert_eq!(p.required_for(Some("codex")), None);
        assert_eq!(p.required_for(None), None);
        let p = Policy::parse(crate::DEFAULT_POLICY).unwrap();
        assert_eq!(p.require, None, "the default policy requires nothing");
        assert_eq!(p.required_for(Some("claude-code")), None);
    }

    #[test]
    fn an_agents_own_level_takes_the_place_of_protection_in_the_same_file() {
        let p = Policy::parse(USER).unwrap();
        assert_eq!(
            level(&p, Some("codex")),
            Some(RequiredLevel::HookAndOsSandbox)
        );
        assert_eq!(level(&p, Some("gemini-cli")), Some(RequiredLevel::HookOnly));
        // A program that is no known agent gets `protection` alone.
        assert_eq!(level(&p, None), Some(RequiredLevel::HookAndOsSandbox));
        assert_eq!(
            p.required_for(Some("codex")).unwrap().by,
            RequiredBy::Policy
        );
    }

    #[test]
    fn bad_levels_ids_and_keys_are_rejected() {
        for bad in [
            "version: 1\nrequire:\n  protection: os-sandbox\n",
            "version: 1\nrequire:\n  protection: none\n",
            "version: 1\nrequire:\n  level: hook-only\n",
            "version: 1\nrequire:\n  agents:\n    Claude Code: hook-only\n",
            "version: 1\nrequire:\n  agents:\n    codex: sandbox\n",
            "version: 1\nrequire: hook-only\n",
        ] {
            assert!(Policy::parse(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn a_repository_raises_the_level_and_never_lowers_it() {
        let user = Policy::parse(USER).unwrap();
        // Every way a repository could try to lower it: a lower level for
        // all agents, for one agent, and for the agent the user lowered.
        for lower in [
            "version: 1\nrequire:\n  protection: hook-only\n",
            "version: 1\nrequire:\n  agents:\n    codex: hook-only\n",
            "version: 1\nrequire: {}\n",
        ] {
            let repo = RepoPolicy::parse(lower).unwrap();
            for trusted in [false, true] {
                let merged = repo.merge(&user, trusted).unwrap();
                assert_eq!(
                    merged.required_for(Some("codex")),
                    user.required_for(Some("codex")),
                    "{lower}"
                );
                assert_eq!(merged.required_for(None), user.required_for(None));
            }
        }
        // Raising: the agent the user lowered, and every agent of a user
        // policy that requires nothing.
        let raise =
            RepoPolicy::parse("version: 1\nrequire:\n  protection: hook-and-os-sandbox\n").unwrap();
        let merged = raise.merge(&user, false).unwrap();
        let gemini = merged.required_for(Some("gemini-cli")).unwrap();
        assert_eq!(gemini.level, RequiredLevel::HookAndOsSandbox);
        assert_eq!(gemini.by, RequiredBy::Repository);
        // An equal level keeps the person's own policy as its source.
        assert_eq!(
            merged.required_for(Some("codex")).unwrap().by,
            RequiredBy::Policy
        );
        let none = Policy::parse("version: 1\n").unwrap();
        let merged = raise.merge_deny(&none).unwrap();
        assert_eq!(
            level(&merged, Some("pi")),
            Some(RequiredLevel::HookAndOsSandbox)
        );
    }

    #[test]
    fn the_strictest_of_every_source_applies() {
        let mut p = Policy::parse("version: 1\nrequire:\n  protection: hook-only\n").unwrap();
        let pack = Require {
            protection: None,
            agents: [("codex".to_owned(), RequiredLevel::HookAndOsSandbox)].into(),
        };
        p.add_requirement(RequiredBy::Pack("team".into()), &pack);
        let codex = p.required_for(Some("codex")).unwrap();
        assert_eq!(codex.level, RequiredLevel::HookAndOsSandbox);
        assert_eq!(codex.by, RequiredBy::Pack("team".into()));
        assert_eq!(level(&p, Some("cursor")), Some(RequiredLevel::HookOnly));
    }
}

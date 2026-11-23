//! The protection score of each tier `openmoat run` can start here (ADR-108),
//! for `openmoat doctor`: the plan a run of that tier would start with, scored
//! like the run's own record, and the hook alone, which scores 0.

use openmoat_core::boundary::{ProtectionScore, ToolToken};
use serde::Serialize;

use super::boundary::{Plan, plan};
use super::isolation::{Asked, Lightweight, Offered, Tier};
use super::platform;

/// The left column of each tier's `openmoat doctor` line, which places the
/// lines in its `OpenMoat` section.
pub const LABEL: &str = "protection";

/// One tier's score here, or why the tier cannot start.
#[derive(Debug, Clone, Serialize)]
pub struct TierScore {
    /// `isolated`, `lightweight` or `hook-only`.
    pub tier: &'static str,
    /// The plan's score; `None` when the tier cannot start here.
    pub score: Option<ProtectionScore>,
    /// Why the tier cannot start here, or what the hook alone leaves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

impl TierScore {
    /// The `openmoat doctor` line.
    pub fn line(&self) -> String {
        let text = match (&self.score, &self.why) {
            (Some(score), _) => score.line(),
            (None, Some(why)) => why.clone(),
            (None, None) => String::new(),
        };
        format!("{LABEL:<16} {:<11} {text}", self.tier)
    }

    /// Whether the line is a warning: a tier that starts with less than its
    /// whole score, or none at all.
    pub fn warns(&self) -> bool {
        self.score.as_ref().is_none_or(|s| !s.complete())
    }
}

/// What a session gets from the hook alone: no kernel feature is in force, so
/// an allowed call runs with the person's permissions.
const HOOK_ONLY: &str = "0/100: no kernel feature is in force; an allowed call runs with your \
                         permissions, so a classifier mistake is a bypass. `openmoat run` or the \
                         agent's own sandbox confines it";

/// The tiers `openmoat run` can start here, strongest first, then the hook alone.
pub fn tiers() -> Vec<TierScore> {
    let mut out = Vec::new();
    if let Some(why) = platform::unavailable() {
        out.push(TierScore {
            tier: "run",
            score: None,
            why: Some(format!("0/100: {why}")),
        });
    } else {
        let kernel = platform::landlock();
        let scored = |tier: &Tier, port_only: Option<String>| {
            plan(Plan {
                asked: Asked::Default,
                tier,
                port_only,
                kernel: kernel.as_ref(),
                token: ToolToken::UnknownAgent,
                port: None,
                project_top_open: false,
            })
            .score
        };
        match platform::isolation() {
            Offered::Available => out.push(TierScore {
                tier: "isolated",
                score: scored(&Tier::Isolated { asked: false }, None),
                why: None,
            }),
            Offered::Unavailable(why) => out.push(TierScore {
                tier: "isolated",
                score: None,
                why: Some(format!("cannot start here: {why}")),
            }),
            Offered::Not => {}
        }
        let lightweight = Tier::Lightweight(Lightweight::Platform);
        out.push(TierScore {
            tier: "lightweight",
            score: scored(&lightweight, platform::no_network_namespace()),
            why: None,
        });
    }
    out.push(TierScore {
        tier: "hook-only",
        score: None,
        why: Some(HOOK_ONLY.to_owned()),
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hook alone is always last and scores 0; every tier here that can
    /// start has a score of at most 100.
    #[test]
    fn the_hook_alone_is_last_and_every_tier_is_scored() {
        let tiers = tiers();
        let last = tiers.last().unwrap();
        assert_eq!(last.tier, "hook-only");
        assert!(last.line().contains("0/100"), "{}", last.line());
        assert!(last.warns());
        for tier in &tiers {
            if let Some(score) = &tier.score {
                assert!(score.points <= 100, "{tier:?}");
            }
            assert!(tier.line().starts_with("protection"), "{}", tier.line());
        }
    }
}

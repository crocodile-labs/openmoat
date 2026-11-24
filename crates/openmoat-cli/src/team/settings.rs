//! The settings a team bundle requires (ADR-119): each one only its stricter
//! value, applied over the person's own policy as the strictest of the two.
//! A bundle that names the weaker value of a setting does not parse: it would
//! read as a requirement and require nothing.

use anyhow::{Result, bail};
use openmoat_core::{ForeignHooks, HookSettings, Policy, Unattended};
use serde::{Deserialize, Serialize};

/// `settings:` of a bundle's manifest, by the policy keys they raise.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// `sandbox.strict: true`: `openmoat run` starts only with its whole
    /// protection score (ADR-108).
    #[serde(
        rename = "sandbox.strict",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sandbox_strict: Option<bool>,
    /// The least `sandbox.package_min_release_age_days` (ADR-030).
    #[serde(
        rename = "sandbox.package_min_release_age_days",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_min_release_age_days: Option<u16>,
    /// `hooks.foreign: hold` (ADR-109).
    #[serde(
        rename = "hooks.foreign",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hooks_foreign: Option<ForeignHooks>,
    /// `unattended: review` (ADR-102).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unattended: Option<Unattended>,
    /// `mcp.trust_first_sight: false` (ADR-032).
    #[serde(
        rename = "mcp.trust_first_sight",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mcp_trust_first_sight: Option<bool>,
    /// `mcp.allow_sampling: false` (ADR-114).
    #[serde(
        rename = "mcp.allow_sampling",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mcp_allow_sampling: Option<bool>,
}

impl Settings {
    /// Refuse a setting given its weaker value.
    pub fn check(&self) -> Result<()> {
        let weaker = [
            ("sandbox.strict", self.sandbox_strict == Some(false), "true"),
            (
                "sandbox.package_min_release_age_days",
                self.package_min_release_age_days == Some(0),
                "a number of days of at least 1",
            ),
            (
                "hooks.foreign",
                self.hooks_foreign == Some(ForeignHooks::Warn),
                "hold",
            ),
            (
                // The policy key and its rule share the name.
                openmoat_core::rule_id::UNATTENDED,
                self.unattended == Some(Unattended::Defer),
                "review",
            ),
            (
                "mcp.trust_first_sight",
                self.mcp_trust_first_sight == Some(true),
                "false",
            ),
            (
                "mcp.allow_sampling",
                self.mcp_allow_sampling == Some(true),
                "false",
            ),
        ];
        if let Some((key, _, strict)) = weaker.iter().find(|(_, weak, _)| *weak) {
            bail!(
                "settings.`{key}`: a team bundle requires only the stricter value ({strict}); \
                 leave the key out to require nothing"
            );
        }
        Ok(())
    }

    /// `policy` with every required setting at least as strict as required.
    pub fn apply(&self, policy: &mut Policy) {
        if self.sandbox_strict == Some(true) {
            policy.sandbox.get_or_insert_default().strict = true;
        }
        if let Some(days) = self.package_min_release_age_days {
            let now = policy.package_min_release_age_days();
            // 0 is off, the weakest value.
            let days = if now == 0 { days } else { now.max(days) };
            policy
                .sandbox
                .get_or_insert_default()
                .package_min_release_age_days = Some(days);
        }
        if self.hooks_foreign == Some(ForeignHooks::Hold) {
            policy.hooks = Some(HookSettings {
                foreign: ForeignHooks::Hold,
            });
        }
        if self.unattended == Some(Unattended::Review) {
            policy.unattended = Some(Unattended::Review);
        }
        if let Some(mcp) = policy.mcp.as_mut() {
            if self.mcp_trust_first_sight == Some(false) {
                mcp.trust_first_sight = false;
            }
            if self.mcp_allow_sampling == Some(false) {
                mcp.allow_sampling = false;
            }
        }
    }

    /// Each required setting `policy` does not have, as `<key>: <what>`.
    pub fn unmet(&self, policy: &Policy) -> Vec<String> {
        let mut out = Vec::new();
        if self.sandbox_strict == Some(true) && !policy.sandbox_strict() {
            out.push("sandbox.strict: off, the bundle requires it on".to_owned());
        }
        if let Some(days) = self.package_min_release_age_days {
            let now = policy.package_min_release_age_days();
            if now == 0 || now < days {
                out.push(format!(
                    "sandbox.package_min_release_age_days: {now}, the bundle requires at least \
                     {days}"
                ));
            }
        }
        if self.hooks_foreign == Some(ForeignHooks::Hold)
            && policy.foreign_hooks() != ForeignHooks::Hold
        {
            out.push("hooks.foreign: warn, the bundle requires hold".to_owned());
        }
        if self.unattended == Some(Unattended::Review) && policy.unattended() != Unattended::Review
        {
            out.push("unattended: defer, the bundle requires review".to_owned());
        }
        if self.mcp_trust_first_sight == Some(false) && policy.trust_mcp_first_sight() {
            out.push("mcp.trust_first_sight: on, the bundle requires it off".to_owned());
        }
        if self.mcp_allow_sampling == Some(false) && policy.allow_mcp_sampling() {
            out.push("mcp.allow_sampling: on, the bundle requires it off".to_owned());
        }
        out
    }
}

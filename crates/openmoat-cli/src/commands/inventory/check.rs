//! `openmoat inventory --check <bundle>` (ADR-119): how this machine differs
//! from what a team's bundle requires, for a scheduled job or an MDM script.
//! Each difference is one [`Drift`]; any at all exits 1.
//!
//! The bundle is verified against the joined team's pinned key first: an
//! unverified bundle says nothing about what the machine should be, so it is
//! a usage error (64), not drift.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde::Serialize;

use crate::heartbeat::Loaded;
use crate::home::Home;
use crate::install::HostConfig;
use crate::integrity::Lock;
use crate::team::{self, Bundle, TEAM_RULE_PREFIX, bundle};

/// One way the machine differs from the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Drift {
    /// `team`, `bundle`, `lock`, `policy`, `setting`, `rule`, `hook` or
    /// `required-level`.
    pub check: &'static str,
    pub detail: String,
}

fn drift(check: &'static str, detail: impl Into<String>) -> Drift {
    Drift {
        check,
        detail: detail.into(),
    }
}

/// The differences between this machine and the bundle in `dir`.
pub fn run(home: &Home, binary: &Path, dir: &Path) -> Result<Vec<Drift>> {
    let Some(joined) = team::joined(home)? else {
        return Ok(vec![drift(
            "team",
            "this machine is in no team: `openmoat team join <folder> --signer <entry>`",
        )]);
    };
    let signers = team::trusted_signers(home).context(
        "the team's signing key is not pinned by the lock, so the bundle cannot be checked",
    )?;
    let bundle = bundle::verify(home, &signers, dir)?;
    let mut out = Vec::new();
    if bundle.manifest.name != joined.name {
        out.push(drift(
            "team",
            format!(
                "the bundle is team `{}`'s; this machine is in `{}`",
                bundle.manifest.name, joined.name
            ),
        ));
    } else if bundle.digest() != joined.manifest_sha256 {
        let detail = if bundle.manifest.serial > joined.serial {
            format!(
                "serial {} is published, {} is installed: `openmoat team update`",
                bundle.manifest.serial, joined.serial
            )
        } else {
            format!(
                "the installed bundle (serial {}) is not the one in the folder (serial {})",
                joined.serial, bundle.manifest.serial
            )
        };
        out.push(drift("bundle", detail));
    }
    match Lock::load(&home.lock_path()) {
        Ok(lock) => {
            let drifted = lock.verify();
            if !drifted.is_empty() {
                out.push(drift(
                    "lock",
                    format!(
                        "{} pinned file(s) changed: every call is denied until `openmoat doctor`",
                        drifted.len()
                    ),
                ));
            }
        }
        Err(e) => out.push(drift("lock", format!("{e:#}"))),
    }
    match home.load_policy() {
        Ok(policy) => {
            out.extend(
                bundle
                    .manifest
                    .settings
                    .unmet(&policy)
                    .into_iter()
                    .map(|d| drift("setting", d)),
            );
            out.extend(missing_rules(&bundle, &policy));
        }
        Err(e) => out.push(drift("policy", format!("{e:#}"))),
    }
    out.extend(hooks(home, binary, &bundle)?);
    Ok(out)
}

/// The bundle's rules the policy in force does not have.
fn missing_rules(bundle: &Bundle, policy: &openmoat_core::Policy) -> Vec<Drift> {
    let mut out = Vec::new();
    for file in &bundle.files {
        let prefix = format!("{TEAM_RULE_PREFIX}{}:{}:", bundle.manifest.name, file.name);
        let lists = [
            (&file.rules.deny, &policy.deny),
            (&file.rules.review, &policy.repo_review),
        ];
        for (wanted, have) in lists {
            for group in wanted {
                let id = format!("{prefix}{}", group.id);
                if !have.iter().any(|g| g.id == id) {
                    out.push(drift("rule", format!("`{id}` is not in force")));
                }
            }
        }
    }
    out
}

/// Each agent the bundle names whose hook is not installed and running, and
/// each agent below the level the policy requires of it.
fn hooks(home: &Home, binary: &Path, bundle: &Bundle) -> Result<Vec<Drift>> {
    let mut out = Vec::new();
    for host in bundle.manifest.hooks()? {
        let found = crate::protection::of_host(home, binary, host)?;
        if !found.level.hooked() {
            out.push(drift(
                "hook",
                format!("{}: {}", host.display_name(), found.level.label()),
            ));
            continue;
        }
        let config = HostConfig::for_host(home, host)?;
        match crate::heartbeat::check(home, &config) {
            Some(Loaded::Missing { .. }) => out.push(drift(
                "hook",
                format!("{}: it ran without OpenMoat's hook", host.display_name()),
            )),
            Some(Loaded::Unchecked { tool, .. }) => out.push(drift(
                "hook",
                format!(
                    "{}: a `{tool}` call ran without reaching OpenMoat's hook",
                    host.display_name()
                ),
            )),
            _ => {}
        }
    }
    for found in crate::protection::report(home, binary)? {
        if !found.meets_required() {
            out.push(drift(
                "required-level",
                format!(
                    "{}: {} is below the level the policy requires",
                    found.name,
                    found.level.label()
                ),
            ));
        }
    }
    Ok(out)
}

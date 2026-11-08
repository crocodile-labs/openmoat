//! The directory grants `openmoat policy upgrade` brings up to date: the rules
//! an earlier release's `openmoat allow --dir` wrote, which leave out only the
//! protections of their day, become grants that leave out what the policy holds
//! for review now (`approvals::DirGrant`, ADR-007 amendment of 2026-11-07).
//! Shown as their own item, asked with the rest, written before the re-pin.

use anyhow::{Context as _, Result};
use openmoat_core::Policy;

use crate::approvals::{DirGrant, Overlay, Places};
use crate::home::Home;

/// The overlay with its old `--dir` rules turned into grants.
pub(super) struct Migration {
    /// `approved.yaml` as it is.
    pub before: String,
    /// `approved.yaml` with the grants.
    pub after: String,
    overlay: Overlay,
    made: Vec<DirGrant>,
}

impl Migration {
    /// The grants `home`'s overlay needs under `policy_text`, the policy the
    /// upgrade leaves; `None` when it has no old `--dir` rule.
    pub fn for_home(home: &Home, policy_text: &str) -> Result<Option<Self>> {
        let current = Overlay::load(&home.overlay_path())?;
        if current.old_dir_rules().next().is_none() {
            return Ok(None);
        }
        let policy = Policy::parse(policy_text).context("reading the upgraded policy")?;
        let mut overlay = current.clone();
        let made = overlay.migrate_dirs(&policy, &Places::here(home)?);
        Ok(Some(Self {
            before: current.text()?,
            after: overlay.text()?,
            overlay,
            made,
        }))
    }

    /// One line per grant, for the summary.
    pub fn lines(&self) -> Vec<String> {
        self.made.iter().map(line).collect()
    }

    pub fn save(&self, home: &Home) -> Result<()> {
        self.overlay.save(&home.overlay_path())
    }
}

/// `` `approved-1` (/w/shared): what the policy holds for review in it stays
/// held, protections added later included ``, and what it keeps of its own.
fn line(grant: &DirGrant) -> String {
    let kept = match grant.except.len() {
        0 => String::new(),
        n => format!(
            "; it keeps out {} the policy no longer names",
            crate::report::count(n, "path")
        ),
    };
    format!(
        "`{}` ({}): what the policy holds for review in it stays held, protections \
         added later included{kept}",
        grant.id,
        grant.dir.join(", ")
    )
}

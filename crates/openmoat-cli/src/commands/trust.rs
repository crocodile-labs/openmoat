//! `moat trust`: let a repository policy's allow rules apply (ADR-022).
//!
//! Person-only, like `moat allow`: trust widens the policy, so it needs a
//! terminal and an intact lock, and the default policy denies it to agents.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Kind, REPO_RULE_PREFIX};

use crate::cli::TrustArgs;
use crate::exit::Code;
use crate::home::{self, Home};
use crate::integrity::{self, HookPins};
use crate::render::Deferred;
use crate::trust::Trust;
use crate::{context, project, repo};

pub fn run(args: &TrustArgs) -> Result<Code> {
    crate::terminal::refuse_agent("moat trust")?;
    if !crate::terminal::interactive() {
        bail!("`moat trust` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    integrity::refuse_drift(&home, "change trust")?;
    let start = context::absolute(args.repo.as_deref().unwrap_or(Path::new(".")))?;
    let root = project::root_of(&start, &home::user_home()?).with_context(|| {
        format!(
            "{} is not in a project: it is the home directory, one of its ancestors or a filesystem root",
            start.display()
        )
    })?;

    let path = home.trust_path();
    let mut trust = Trust::load(&path)?;
    let mut out = Deferred::default();
    if args.revoke {
        if trust.repos.remove(&repo::root_key(&root)?).is_none() {
            writeln!(out, "{} is not trusted; nothing to revoke", root.display())?;
            out.finish()?;
            return Ok(Code::Ok);
        }
        writeln!(
            out,
            "✔ revoked: the repository policy of {} only tightens again",
            root.display()
        )?;
    } else {
        // A file that does not parse cannot be trusted: `find` says why.
        let found = repo::find(&home, &root)?
            .with_context(|| format!("{} has no .moat/policy.yaml", root.display()))?;
        for group in &found.policy.allow {
            writeln!(
                out,
                "  allow {REPO_RULE_PREFIX}{}: {}",
                group.id,
                patterns(group)
            )?;
        }
        writeln!(
            out,
            "✔ trusted {}  sha256:{}: its {} allow rule(s) apply until the file changes",
            found.path.display(),
            found.digest,
            found.policy.allow.len()
        )?;
        trust.repos.insert(found.root, found.digest);
    }
    trust.save(&path)?;
    let lock = integrity::repin(&home, &crate::install::hook_binary()?, HookPins::Keep)?;
    writeln!(out, "✔ lock re-pinned ({} files)", lock.entries.len())?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `shell: a, b; net: c`: what one allow group lets through.
fn patterns(group: &openmoat_core::RuleGroup) -> String {
    Kind::ALL
        .into_iter()
        .filter(|k| !group.patterns(*k).is_empty())
        .map(|k| format!("{}: {}", k.as_str(), group.patterns(k).join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}

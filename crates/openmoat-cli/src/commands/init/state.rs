//! OpenMoat's own state as `init` writes it: the state directory, the default
//! policy, the audit log and its keys, and the search-path snapshot.

use std::io::Write as _;

use anyhow::{Result, bail};

use crate::environment::Snapshot;
use crate::home::Home;
use crate::render::Deferred;

/// OpenMoat's own state: the directory, the default policy (kept when there is
/// one), the audit log and the search-path snapshot `snapshot` (the recorded
/// one kept when `unattended` or when [`search_path`] found nothing); the
/// update a kept policy can take from this release's default.
pub(super) fn write(
    home: &Home,
    dry_run: bool,
    unattended: bool,
    snapshot: Option<&Snapshot>,
    out: &mut Deferred,
) -> Result<Option<String>> {
    let prefix = if dry_run { "would" } else { "✔" };
    if !dry_run {
        home.ensure()?;
    }
    writeln!(out, "{prefix} state directory  {}", home.root().display())?;

    let policy_path = home.policy_path();
    let wrote_policy = if dry_run {
        !policy_path.exists()
    } else {
        home.ensure_policy()?
    };
    let mut update = None;
    if wrote_policy {
        writeln!(
            out,
            "{prefix} policy           {} (defaults v1)",
            policy_path.display()
        )?;
    } else {
        writeln!(out, "✔ policy           {} (kept)", policy_path.display())?;
        update = crate::upgrade::available(home);
        if let Some(update) = &update {
            writeln!(
                out,
                "! policy update    {update}: `openmoat policy upgrade` shows them and asks"
            )?;
        }
    }

    // The log and its key (ADR-101), so the first call is keyed.
    let kept = if dry_run {
        None
    } else {
        crate::audit_key::open(home)?
    };
    writeln!(
        out,
        "{prefix} audit log        {}",
        home.audit_path().display()
    )?;
    if let Some(kept) = kept {
        writeln!(
            out,
            "  a new audit log starts with a new audit key; the previous key is kept as {} \
             (it still checks a log you moved aside)",
            kept.display()
        )?;
    }
    // The key checkpoints are signed with (ADR-110), kept across new logs:
    // its public key is what others check them with.
    if !dry_run && crate::audit_signing::ensure(home)?.1 {
        writeln!(
            out,
            "✔ audit signing    {} (its public key: `openmoat doctor`)",
            crate::audit_signing::path(home).display()
        )?;
    }

    if dry_run {
        writeln!(
            out,
            "would environment      {}",
            home.environment_path().display()
        )?;
    } else if unattended && home.environment_path().is_file() {
        writeln!(
            out,
            "· environment      {} kept: no person at a terminal to record a new search path",
            home.environment_path().display()
        )?;
    } else if let Some(snapshot) = snapshot {
        snapshot.save(&home.environment_path())?;
        writeln!(
            out,
            "✔ environment      {} ({} dirs, {} programs pinned)",
            home.environment_path().display(),
            snapshot.path.len(),
            snapshot.programs.len()
        )?;
    } else {
        writeln!(
            out,
            "· environment      {} kept",
            home.environment_path().display()
        )?;
    }
    Ok(update)
}

/// This shell's search path, as `init` records it; `None` when it finds none
/// of [`PINNED_PROGRAMS`](crate::environment::PINNED_PROGRAMS) (an empty or
/// broken `PATH`, a service's bare environment) and a snapshot is recorded
/// already, which is then kept. Without one it is refused: a snapshot that
/// pins nothing would check no program the guard resolves, and `init` would
/// say it succeeded.
pub(super) fn search_path(home: &Home) -> Result<Option<Snapshot>> {
    let snapshot = Snapshot::capture();
    if !snapshot.programs.is_empty() {
        return Ok(Some(snapshot));
    }
    if home.environment_path().is_file() {
        return Ok(None);
    }
    bail!(
        "this shell's PATH finds none of the programs OpenMoat pins (sh, git, curl, …), so \
         there is no search path to record and nothing was changed; run `openmoat init` from a \
         normal shell"
    )
}

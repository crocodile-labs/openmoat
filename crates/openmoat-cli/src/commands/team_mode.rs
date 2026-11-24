//! `openmoat team join`, `update` and `leave` (ADR-119): a team's signed
//! bundle as a managed layer over the person's policy.
//!
//! Person-only, like `openmoat policy install`: each changes what the guard
//! decides by and re-pins the lock, so each needs a terminal, no agent among
//! its parents and an intact lock, and the default policy denies `openmoat
//! team join|update|leave` to agents. What a change widens is shown by the
//! never-widen check (ADR-111) and waits for the person's answer.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::Policy;

use crate::cli::{TeamJoinArgs, TeamUpdateArgs};
use crate::exit::Code;
use crate::home::{Home, create_private_dir, write_private};
use crate::integrity::{self, HookPins};
use crate::render::Deferred;
use crate::team::{self, Bundle, Joined, Layer, bundle};

/// The checks every team command makes before it writes; the state directory.
/// A later proof of the person's presence (the possession gate, ADR-117)
/// goes here, the one check all three commands share.
fn person(command: &str, doing: &str) -> Result<Home> {
    crate::terminal::refuse_agent(command)?;
    if !crate::terminal::interactive() {
        bail!("`{command}` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    integrity::refuse_drift(&home, doing)?;
    Ok(home)
}

/// The bundle's folder, canonical. A URL is refused: OpenMoat fetches
/// nothing, so the person clones the repository and gives the clone.
fn source_dir(given: &Path) -> Result<PathBuf> {
    let text = given.to_string_lossy();
    ensure!(
        !text.contains("://") && !text.starts_with("git@"),
        "`{text}` is a URL: OpenMoat fetches nothing; clone the team's repository and give the \
         clone's folder"
    );
    let dir = fs::canonicalize(given).with_context(|| format!("reading {}", given.display()))?;
    ensure!(dir.is_dir(), "{} is not a folder", dir.display());
    Ok(dir)
}

pub fn join(args: &TeamJoinArgs) -> Result<Code> {
    let home = person("openmoat team join", "join a team")?;
    if let Some(joined) = team::joined(&home)? {
        bail!(
            "this machine is in team `{}` already; `openmoat team update` installs its newer \
             bundle, `openmoat team leave` leaves it",
            joined.name
        );
    }
    let source = source_dir(&args.bundle)?;
    let line = crate::signing::team_signer_line(&args.signer)?;
    create_private_dir(&home.team_dir())?;
    let staged = home.team_dir().join(".staged_signers");
    write_private(&staged, format!("{line}\n").as_bytes())?;
    let result = join_with(&home, &source, &staged);
    let _ = fs::remove_file(&staged);
    result
}

fn join_with(home: &Home, source: &Path, staged: &Path) -> Result<Code> {
    let bundle = bundle::verify(home, staged, source)?;
    let before = home.load_policy_with_team(Layer::None)?;
    let after = home.load_policy_with_team(Layer::This(&bundle))?;
    let mut out = Deferred::default();
    let what = format!("Joining team `{}`", bundle.manifest.name);
    if !accepted(&mut out, &what, &before, &after)? {
        writeln!(out, "nothing changed")?;
        out.finish()?;
        return Ok(Code::Usage);
    }
    let key = fs::read(staged).with_context(|| format!("reading {}", staged.display()))?;
    write_private(&team::signers_path(home), &key)?;
    install(home, &bundle, source)?;
    let pinned = repin(home)?;
    summary(&mut out, &bundle, "joined")?;
    writeln!(out, "✔ lock re-pinned ({pinned} files)")?;
    out.finish()?;
    Ok(Code::Ok)
}

pub fn update(args: &TeamUpdateArgs) -> Result<Code> {
    let home = person("openmoat team update", "update the team bundle")?;
    let joined = team::joined(&home)?.context(
        "no team is joined here; `openmoat team join <folder> --signer <entry>` joins one",
    )?;
    let signers = team::trusted_signers(&home).context(
        "the team's signing key is not pinned by the lock; leave the team and join it again",
    )?;
    let source = match &args.bundle {
        Some(given) => source_dir(given)?,
        None => source_dir(Path::new(&joined.source))?,
    };
    let bundle = bundle::verify(&home, &signers, &source)?;
    let mut out = Deferred::default();
    if let Some(done) = current(&mut out, &joined, &bundle)? {
        out.finish()?;
        return Ok(done);
    }
    let before = home.load_policy()?;
    let after = home.load_policy_with_team(Layer::This(&bundle))?;
    let what = format!(
        "Updating team `{}` from serial {} to {}",
        joined.name, joined.serial, bundle.manifest.serial
    );
    if !accepted(&mut out, &what, &before, &after)? {
        writeln!(out, "nothing changed")?;
        out.finish()?;
        return Ok(Code::Usage);
    }
    install(&home, &bundle, &source)?;
    let pinned = repin(&home)?;
    summary(&mut out, &bundle, "updated")?;
    writeln!(out, "✔ lock re-pinned ({pinned} files)")?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `Some` when nothing is to be installed: the same bundle, or one refused
/// for its name or serial.
fn current(out: &mut Deferred, joined: &Joined, bundle: &Bundle) -> Result<Option<Code>> {
    ensure!(
        bundle.manifest.name == joined.name,
        "the bundle is team `{}`'s, not `{}`'s: leave this team first",
        bundle.manifest.name,
        joined.name
    );
    if bundle.digest() == joined.manifest_sha256 {
        writeln!(
            out,
            "✔ team `{}` is current (serial {})",
            joined.name, joined.serial
        )?;
        return Ok(Some(Code::Ok));
    }
    ensure!(
        bundle.manifest.serial > joined.serial,
        "refusing the bundle: its serial {} is not above the installed {} (a team raises the \
         serial with every bundle it publishes, so an older bundle cannot be installed again)",
        bundle.manifest.serial,
        joined.serial
    );
    Ok(None)
}

pub fn leave() -> Result<Code> {
    let home = person("openmoat team leave", "leave the team")?;
    let joined = team::joined(&home)?.context("no team is joined here")?;
    let before = home.load_policy()?;
    let after = home.load_policy_with_team(Layer::None)?;
    let mut out = Deferred::default();
    let report = crate::widen::compare(&before, &after, &[])?;
    writeln!(
        out,
        "Leaving team `{}` removes its rules and settings:",
        joined.name
    )?;
    crate::widen::write_widenings(&mut out, &report, false)?;
    if !super::edit::confirm(&mut out, "Leave the team? [y/N] ")? {
        writeln!(out, "nothing changed")?;
        out.finish()?;
        return Ok(Code::Usage);
    }
    let files = team::installed_files(&home);
    for file in files.iter().chain([&home.team_path()]) {
        let _ = fs::remove_file(file);
    }
    let _ = fs::remove_dir_all(team::rules_dir(&home));
    // Every team file stays pinned, as absent: one that appears later is drift.
    let pinned = repin(&home)?;
    writeln!(
        out,
        "✔ left team `{}`; its rules no longer apply",
        joined.name
    )?;
    writeln!(out, "✔ lock re-pinned ({pinned} files)")?;
    out.finish()?;
    Ok(Code::Ok)
}

/// Show what moving from `before` to `after` changes; `true` when it may go
/// ahead: it widens nothing, or the person accepted what it widens.
fn accepted(out: &mut Deferred, what: &str, before: &Policy, after: &Policy) -> Result<bool> {
    let report = crate::widen::compare(before, after, &[])?;
    if !report.widens() && !report.unchecked() {
        writeln!(out, "✔ {what} moves no call toward allow")?;
        return Ok(true);
    }
    writeln!(out, "{what} widens your policy:")?;
    crate::widen::write_widenings(out, &report, false)?;
    super::edit::confirm(out, "Accept these changes? [y/N] ")
}

/// Write the verified bytes, rule files first and the record last, so a
/// write cut short leaves a record whose digests do not match: drift, which
/// the guard denies, never a half-applied layer.
fn install(home: &Home, bundle: &Bundle, source: &Path) -> Result<()> {
    let rules = team::rules_dir(home);
    let _ = fs::remove_dir_all(&rules);
    create_private_dir(&rules)?;
    for file in &bundle.files {
        write_private(&team::rule_path(home, &file.name), file.text.as_bytes())?;
    }
    write_private(&team::manifest_path(home), &bundle.manifest_bytes)?;
    write_private(&team::signature_path(home), &bundle.signature)?;
    Joined::of(bundle, source).save(&home.team_path())
}

/// Re-pin, keeping every pin, with the signing and team files as they are now.
fn repin(home: &Home) -> Result<usize> {
    let files = integrity::signing_files(home);
    let lock = integrity::repin_with(
        home,
        &crate::install::hook_binary()?,
        HookPins::Keep,
        &files,
        &[],
    )?;
    Ok(lock.entries.len())
}

fn summary(out: &mut Deferred, bundle: &Bundle, how: &str) -> Result<()> {
    let m = &bundle.manifest;
    let (deny, review) = bundle.files.iter().fold((0, 0), |(d, r), f| {
        (d + f.rules.deny.len(), r + f.rules.review.len())
    });
    writeln!(
        out,
        "✔ {how} team `{}` (serial {}) signed by {}: {deny} deny, {review} review rule(s) in {} \
         file(s)",
        m.name,
        m.serial,
        bundle.signer,
        bundle.files.len()
    )?;
    let settings = serde_json::to_value(&m.settings)?;
    if let Some(map) = settings.as_object().filter(|m| !m.is_empty()) {
        for (key, value) in map {
            writeln!(out, "  requires {key}: {value}")?;
        }
    }
    if !m.require_hooks.is_empty() {
        writeln!(
            out,
            "  requires the hook of: {}",
            m.require_hooks.join(", ")
        )?;
    }
    Ok(())
}

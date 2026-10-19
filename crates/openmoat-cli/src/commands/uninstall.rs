//! `moat uninstall`: take OpenMoat's hooks and sandbox settings out of the agents.
//!
//! Each host file is undone by removing exactly what `moat init` writes. When
//! what is left equals one of the backups `init` took, that backup's bytes are
//! written back, so an untouched file comes back byte for byte; when it is
//! empty and no backup matches, `init` created the file and it is deleted.
//! Otherwise the user changed the file since, and their changes stay. Only the
//! backups `hosts.json` records as OpenMoat's are deleted: a file of the
//! user's at a backup's name stays.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::cli::UninstallArgs;
use crate::exit::Code;
use crate::home::{Home, user_home, write_private};
use crate::install::{self, HostConfig, Recorded, read_or_empty};
use crate::integrity;
use crate::render::Deferred;
use crate::sandbox::{claude, codex, codex_config_path, cursor};

pub fn run(args: &UninstallArgs) -> Result<Code> {
    crate::terminal::refuse_agent("moat uninstall")?;
    if !crate::terminal::interactive() {
        bail!("`moat uninstall` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    let hosts = match &args.hosts {
        Some(explicit) => explicit.clone(),
        None => Host::ALL
            .into_iter()
            .filter(|h| HostConfig::for_host(&home, *h).is_ok())
            .collect(),
    };
    let mut out = Deferred::default();
    // Before the record forgets where each agent is: the wrapped servers point at
    // `moat mcp proxy`, which outlives the hooks only as a dangling path.
    if let Err(e) = super::mcp::unwrap_servers(&home, &hosts, &[], &mut out) {
        writeln!(
            out,
            "! mcp servers      {e:#}; `moat mcp unwrap` restores the wrapped ones"
        )?;
    }
    let mut undone = Vec::new();
    let mut recorded = Recorded::load(&home)?;
    for host in hosts.iter().copied() {
        let config = HostConfig::for_host(&home, host)?;
        // Claude Code keeps its sandbox block in the same file as its hooks.
        let sandbox_too = host == Host::ClaudeCode;
        let owned = &recorded.claude_rules;
        let ours = &recorded.backups;
        let strip =
            |root: &mut Value| config.remove(root) | (sandbox_too && claude::remove(root, owned));
        let path = &config.settings_path;
        let mut files = vec![(path.clone(), undo_json(path, ours, strip)?)];
        if host == Host::Codex {
            let path = codex_config_path(&home)?;
            files.push((path.clone(), undo_toml(&path, ours)?));
        }
        if host == Host::Cursor {
            let path = crate::sandbox::install::settings_path(&home, host)?;
            files.push((path.clone(), undo_json(&path, ours, cursor::remove)?));
        }
        // OpenClaw's hook is the plugin file `init` wrote, which nothing else owns.
        if host == Host::OpenClaw
            && let Some(plugin) = install::openclaw::remove_plugin(&config)?
        {
            files.push((plugin, Some(Undone::Deleted)));
        }
        if files.iter().all(|(_, done)| done.is_none()) {
            writeln!(out, "· {:<16} not set up", host.display_name())?;
        }
        for (path, done) in files {
            if let Some(done) = done {
                writeln!(
                    out,
                    "✔ {:<16} {} {done}",
                    host.display_name(),
                    path.display()
                )?;
                undone.push(path);
            }
        }
    }
    // The files are undone first: until then the record says where they are.
    let before = recorded.dirs.len();
    recorded
        .dirs
        .retain(|id, _| !hosts.iter().any(|h| h.id() == id));
    let forgot_rules = hosts.contains(&Host::ClaudeCode) && !recorded.claude_rules.is_empty();
    if forgot_rules {
        recorded.claude_rules.clear();
    }
    let backups_before = recorded.backups.len();
    recorded.backups.retain(|b| b.exists());
    let mut rewritten = Vec::new();
    if recorded.dirs.len() != before || forgot_rules || recorded.backups.len() != backups_before {
        recorded.save(&home)?;
        rewritten.push(home.hosts_path());
    }
    integrity::unpin(&home, &undone, &rewritten)?;
    // If the proxy service was installed, stop and remove it alongside the
    // hooks: leaving it behind would keep listening with a stale binary
    // reference once hooks are gone.
    match super::service::manager(&home).and_then(|m| m.uninstall()) {
        Ok(Some(path)) => writeln!(out, "✔ proxy service    removed: {}", path.display())?,
        Ok(None) => {}
        Err(e) => writeln!(
            out,
            "! proxy service    {e:#}; `moat proxy uninstall` removes it by hand"
        )?,
    }
    if args.purge {
        purge(&home)?;
        writeln!(out, "✔ state directory  {} deleted", home.root().display())?;
    } else if home.exists() {
        writeln!(
            out,
            "· state directory  {} kept (policy, audit log); `moat uninstall --purge` deletes it",
            home.root().display()
        )?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// What happened to one host file, worded to follow its path.
enum Undone {
    Restored(PathBuf),
    Deleted,
    Stripped(Vec<PathBuf>),
}

impl std::fmt::Display for Undone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Restored(backup) => write!(f, "restored from {}", backup.display()),
            Self::Deleted => write!(f, "deleted (moat init created it)"),
            Self::Stripped(kept) if kept.is_empty() => {
                write!(f, "OpenMoat's entries removed, your changes kept")
            }
            Self::Stripped(kept) => {
                let kept: Vec<String> = kept.iter().map(|p| p.display().to_string()).collect();
                write!(
                    f,
                    "OpenMoat's entries removed, your changes kept (backup kept: {})",
                    kept.join(", ")
                )
            }
        }
    }
}

/// `strip` is run on the backups too: one it changes was taken between two
/// OpenMoat edits (the sandbox backup of a file the hook edit created), so it
/// is not the user's original. `ours` are the backups OpenMoat created.
fn undo_json(
    path: &Path,
    ours: &[PathBuf],
    strip: impl Fn(&mut Value) -> bool,
) -> Result<Option<Undone>> {
    if !path.is_file() {
        return Ok(None);
    }
    let mut root = read_or_empty(path)?;
    if !strip(&mut root) {
        return Ok(None);
    }
    let backups = install::backups(path);
    let originals: Vec<(&PathBuf, Value)> = backups
        .iter()
        .filter_map(|b| Some((b, read_or_empty(b).ok()?)))
        .filter(|(_, v)| !strip(&mut v.clone()))
        .collect();
    let original = originals.iter().find(|(_, v)| *v == root).map(|(b, _)| *b);
    let created = originals.is_empty() && root == json!({});
    let text = serde_json::to_string_pretty(&root)? + "\n";
    finish(path, &owned(&backups, ours), original, created, &text).map(Some)
}

fn undo_toml(path: &Path, ours: &[PathBuf]) -> Result<Option<Undone>> {
    if !path.is_file() {
        return Ok(None);
    }
    let read = crate::sandbox::install::read_toml;
    let mut doc = read(path)?;
    if !codex::remove(&mut doc) {
        return Ok(None);
    }
    let text = doc.to_string();
    let backups = install::backups(path);
    let originals: Vec<&PathBuf> = backups
        .iter()
        .filter(|b| read(b).is_ok_and(|mut d| !codex::remove(&mut d)))
        .collect();
    let original = originals
        .iter()
        .find(|b| fs::read_to_string(b).is_ok_and(|t| t == text))
        .copied();
    let created = originals.is_empty() && text.trim().is_empty();
    finish(path, &owned(&backups, ours), original, created, &text).map(Some)
}

/// The `backups` OpenMoat created: the only ones uninstall deletes or lists.
fn owned(backups: &[PathBuf], ours: &[PathBuf]) -> Vec<PathBuf> {
    backups
        .iter()
        .filter(|b| ours.contains(b))
        .cloned()
        .collect()
}

/// Write the undone file: the original backup's bytes; nothing when `init`
/// `created` it; else `text`. OpenMoat's backups go once the file is back as
/// it was; `original` may be any file at a backup's name whose content matches.
fn finish(
    path: &Path,
    backups: &[PathBuf],
    original: Option<&PathBuf>,
    created: bool,
    text: &str,
) -> Result<Undone> {
    let undone = match original {
        Some(backup) => {
            let bytes =
                fs::read(backup).with_context(|| format!("reading {}", backup.display()))?;
            write_private(path, &bytes)?;
            Undone::Restored(backup.clone())
        }
        None if created => {
            fs::remove_file(path).with_context(|| format!("deleting {}", path.display()))?;
            Undone::Deleted
        }
        None => {
            write_private(path, text.as_bytes())?;
            return Ok(Undone::Stripped(backups.to_vec()));
        }
    };
    for backup in backups {
        fs::remove_file(backup).with_context(|| format!("deleting {}", backup.display()))?;
    }
    Ok(undone)
}

/// Delete the state directory, but only one that looks like OpenMoat's:
/// `MOAT_HOME` may point anywhere, the home directory included.
fn purge(home: &Home) -> Result<()> {
    if !home.exists() {
        return Ok(());
    }
    let root = home.root();
    ensure!(
        root != user_home()? && (home.policy_path().is_file() || home.lock_path().is_file()),
        "{} does not look like OpenMoat's state directory; delete it yourself",
        root.display()
    );
    fs::remove_dir_all(root).with_context(|| format!("deleting {}", root.display()))
}

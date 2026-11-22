//! `openmoat init --format json`: one document on stdout for a script, in
//! place of the text `init` prints. A script cannot answer a question whose
//! text it does not see, so a JSON run asks none: it is refused unless the
//! agents are named (`--hosts`), all taken (`--yes`) or only planned
//! (`--dry-run`), and it never asks the MCP or opt-in questions.

use std::path::Path;

use anyhow::{Result, bail};
use serde::Serialize;

use super::summary;
use crate::cli::{Format, InitArgs};
use crate::home::Home;
use crate::install::HostConfig;
use crate::integrity::{self, Lock};
use crate::protection::Protection;

/// Whether `args` asks for JSON; refused when choosing the agents would ask.
pub(super) fn requested(args: &InitArgs) -> Result<bool> {
    if args.format != Format::Json {
        return Ok(false);
    }
    if args.hosts.is_none() && !args.yes && !args.dry_run {
        bail!(
            "`openmoat init --format json` asks no question, so it needs the agents named: \
             add `--hosts <ids>`, `--yes` (every agent found) or `--dry-run`"
        );
    }
    Ok(true)
}

/// The whole document.
#[derive(Serialize)]
struct Report<'a> {
    version: &'static str,
    dry_run: bool,
    hooks_only: bool,
    home: String,
    binary: String,
    binary_sha256: Option<String>,
    lock_path: String,
    policy_path: String,
    environment_path: String,
    changed: bool,
    lock_entries_count: Option<usize>,
    policy_update: Option<&'a str>,
    hosts: Vec<InstalledHost>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protection: Option<Vec<Protection>>,
}

/// One agent `init` set up (or would set up, in a dry run).
#[derive(Serialize)]
pub(super) struct InstalledHost {
    host: &'static str,
    name: &'static str,
    config_dir: String,
    settings_path: String,
    extra_files: Vec<String>,
    managed_files: Vec<String>,
    events: Vec<&'static str>,
    outcome: &'static str,
    changed: bool,
    backup_path: Option<String>,
    trust_note: Option<&'static str>,
}

/// What `init` did to one agent's files.
pub(super) struct Done {
    /// `installed`, `updated` or `unchanged`.
    pub outcome: &'static str,
    pub changed: bool,
    /// Where the person's own hook was moved.
    pub backup_path: Option<String>,
    pub trust_note: Option<&'static str>,
}

impl InstalledHost {
    pub(super) fn new(config: &HostConfig, done: Done) -> Self {
        let extra_files: Vec<String> = config
            .extra_files()
            .into_iter()
            .map(|p| p.display().to_string())
            .collect();
        let settings_path = config.settings_path.display().to_string();
        let mut managed_files = vec![settings_path.clone()];
        managed_files.extend(extra_files.iter().cloned());
        Self {
            host: config.host.id(),
            name: config.host.display_name(),
            config_dir: config.dir().display().to_string(),
            settings_path,
            extra_files,
            managed_files,
            events: config.hooks.iter().map(|spec| spec.event).collect(),
            outcome: done.outcome,
            changed: done.changed,
            backup_path: done.backup_path,
            trust_note: done.trust_note,
        }
    }
}

/// How the run went, for the document.
pub(super) struct Outcome<'a> {
    pub dry_run: bool,
    pub hooks_only: bool,
    pub steps: &'a summary::Steps,
    /// The lock this run wrote; `None` in a dry run.
    pub lock: Option<&'a Lock>,
}

/// Print the document for `run` and the agents it set up.
pub(super) fn print(
    home: &Home,
    binary: &Path,
    hosts: Vec<InstalledHost>,
    run: &Outcome<'_>,
) -> Result<()> {
    // The hash the lock recorded for the binary; a dry run writes no lock.
    let binary_sha256 = match run.lock {
        Some(lock) => lock.binary_sha256.clone(),
        None => std::fs::read(binary)
            .ok()
            .map(|bytes| integrity::sha256_hex(&bytes)),
    };
    let protection = match run.lock {
        Some(_) => Some(
            crate::protection::report(home, binary)?
                .into_iter()
                .filter(|item| hosts.iter().any(|h| h.host == item.host))
                .collect(),
        ),
        None => None,
    };
    let report = Report {
        version: crate::VERSION,
        dry_run: run.dry_run,
        hooks_only: run.hooks_only,
        home: home.root().display().to_string(),
        binary: binary.display().to_string(),
        binary_sha256,
        lock_path: home.lock_path().display().to_string(),
        policy_path: home.policy_path().display().to_string(),
        environment_path: home.environment_path().display().to_string(),
        changed: run.steps.changed,
        lock_entries_count: run.lock.map(|lock| lock.entries.len()),
        policy_update: run.steps.update.as_deref(),
        hosts,
        protection,
    };
    crate::render::json(&report)
}

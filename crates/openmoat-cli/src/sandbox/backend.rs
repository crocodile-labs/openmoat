//! The sandbox backends, one per [`SandboxFormat`]: how each merges the plan
//! into its file, reports, checks and undoes it. The CLI reaches a host's
//! backend through [`backend`] and names no host.

use std::path::Path;

use anyhow::{Context as _, Result};
use openmoat_hosts::{Host, SandboxFormat};
use serde_json::{Value, json};
use toml_edit::DocumentMut;

use super::install::{Rendered, parse_json, read_toml, unavailable};
use super::{Plan, Report, claude, codex, cursor};
use crate::home::Home;
use crate::install::{Recorded, read_or_empty};
use crate::integrity::Lock;

/// How `moat uninstall` takes a backend's settings out of its file.
#[derive(Clone, Copy)]
pub enum Undo {
    /// The settings share the hook file and go with the hooks; the function
    /// strips them, given the rules `hosts.json` records as OpenMoat's.
    WithHooks(fn(&mut Value, &[String]) -> bool),
    /// A TOML file of its own; the function strips OpenMoat's part.
    Toml(fn(&mut DocumentMut) -> bool),
    /// A JSON file of its own; the function strips OpenMoat's keys.
    Json(fn(&mut Value) -> bool),
}

/// One sandbox settings format's backend.
pub trait SandboxBackend: Sync {
    /// `current` (the text of `host`'s sandbox settings file) with the plan
    /// merged in; `None` when it would not change.
    fn render(
        &self,
        home: &Home,
        host: Host,
        plan: &Plan,
        current: &str,
    ) -> Result<Option<Rendered>>;
    /// What the backend loses and widens against the policy.
    fn report<'a>(&self, plan: &'a Plan) -> &'a Report;
    /// What OpenMoat owns in the file, in the file's own format, as
    /// `moat sandbox show` prints it.
    fn shown(&self, plan: &Plan) -> Result<String>;
    /// Problems with the settings at `path` (its directory exists).
    fn problems(
        &self,
        home: &Home,
        path: &Path,
        plan: &Plan,
        lock: Option<&Lock>,
    ) -> Result<Vec<String>>;
    /// How `moat uninstall` removes the settings.
    fn undo(&self) -> Undo;
    /// Whether the lock pins the file by the part OpenMoat owns rather than whole.
    fn pinned_by_part(&self) -> bool {
        false
    }
    /// Whether the host's own broker masks the policy's secrets from these settings.
    fn masks_secrets(&self) -> bool {
        false
    }
}

/// The backend that writes `format`.
pub fn backend(format: SandboxFormat) -> &'static dyn SandboxBackend {
    match format {
        SandboxFormat::ClaudeSettings => &ClaudeSettings,
        SandboxFormat::CodexProfile => &CodexProfile,
        SandboxFormat::CursorSandbox => &CursorSandbox,
    }
}

const OUT_OF_DATE: &str = "differs from the policy; run `openmoat sandbox sync`";
const NOT_PINNED: &str = "not pinned by the lock; run `openmoat sandbox sync`";

/// Claude Code's `sandbox` block and permission rules, in its hook file.
struct ClaudeSettings;

impl SandboxBackend for ClaudeSettings {
    fn render(
        &self,
        home: &Home,
        host: Host,
        plan: &Plan,
        current: &str,
    ) -> Result<Option<Rendered>> {
        let mut owned = Recorded::load(home)?.claude_rules;
        let mut root = parse_json(current)?;
        let changed = if unavailable(host).is_some() {
            claude::apply_rules(&mut root, &plan.claude, &mut owned)
        } else {
            claude::apply(&mut root, &plan.claude, &mut owned)
        }?;
        Ok(changed.then_some(Rendered {
            text: serde_json::to_string_pretty(&root)? + "\n",
            claude_rules: Some(owned),
        }))
    }

    fn report<'a>(&self, plan: &'a Plan) -> &'a Report {
        &plan.claude.report
    }

    fn shown(&self, plan: &Plan) -> Result<String> {
        let mut doc = json!({});
        claude::apply(&mut doc, &plan.claude, &mut Vec::new())?;
        Ok(serde_json::to_string_pretty(&doc)?)
    }

    fn problems(
        &self,
        home: &Home,
        path: &Path,
        plan: &Plan,
        _lock: Option<&Lock>,
    ) -> Result<Vec<String>> {
        let root = read_or_empty(path)?;
        let mut found = claude::weaknesses(&root, plan.claude.block_reads, plan.proxy_port);
        found.extend(claude::mask::weaknesses(&root, &plan.claude));
        let owned = Recorded::load(home)?.claude_rules;
        if !claude::in_sync(&root, &plan.claude, &owned) {
            found.push(OUT_OF_DATE.to_owned());
        }
        Ok(found)
    }

    fn undo(&self) -> Undo {
        Undo::WithHooks(claude::remove)
    }

    fn masks_secrets(&self) -> bool {
        true
    }
}

/// OpenMoat's permissions profile in Codex's `config.toml`.
struct CodexProfile;

impl SandboxBackend for CodexProfile {
    fn render(
        &self,
        _home: &Home,
        _host: Host,
        plan: &Plan,
        current: &str,
    ) -> Result<Option<Rendered>> {
        let mut doc: DocumentMut = current.parse().context("parsing the settings")?;
        let changed = codex::apply(&mut doc, &plan.codex)?;
        Ok(changed.then_some(Rendered {
            text: doc.to_string(),
            claude_rules: None,
        }))
    }

    fn report<'a>(&self, plan: &'a Plan) -> &'a Report {
        &plan.codex.report
    }

    fn shown(&self, plan: &Plan) -> Result<String> {
        let mut doc = DocumentMut::new();
        codex::apply(&mut doc, &plan.codex)?;
        Ok(doc.to_string())
    }

    fn problems(
        &self,
        _home: &Home,
        path: &Path,
        plan: &Plan,
        lock: Option<&Lock>,
    ) -> Result<Vec<String>> {
        let doc = read_toml(path)?;
        let mut found = codex::weaknesses(&doc, plan.proxy_port.is_some());
        if !codex::in_sync(&doc, &plan.codex) {
            found.push(OUT_OF_DATE.to_owned());
        }
        if lock.is_some_and(|l| !l.pins_codex_profile(path)) {
            found.push(NOT_PINNED.to_owned());
        }
        Ok(found)
    }

    fn undo(&self) -> Undo {
        Undo::Toml(codex::remove)
    }

    fn pinned_by_part(&self) -> bool {
        true
    }
}

/// Cursor's `sandbox.json`.
struct CursorSandbox;

impl SandboxBackend for CursorSandbox {
    fn render(
        &self,
        _home: &Home,
        host: Host,
        plan: &Plan,
        current: &str,
    ) -> Result<Option<Rendered>> {
        if unavailable(host).is_some() {
            return Ok(None);
        }
        let mut root = parse_json(current)?;
        let changed = cursor::apply(&mut root, &plan.cursor)?;
        Ok(changed.then_some(Rendered {
            text: serde_json::to_string_pretty(&root)? + "\n",
            claude_rules: None,
        }))
    }

    fn report<'a>(&self, plan: &'a Plan) -> &'a Report {
        &plan.cursor.report
    }

    fn shown(&self, plan: &Plan) -> Result<String> {
        Ok(serde_json::to_string_pretty(&plan.cursor.settings)?)
    }

    fn problems(
        &self,
        _home: &Home,
        path: &Path,
        plan: &Plan,
        lock: Option<&Lock>,
    ) -> Result<Vec<String>> {
        let root = read_or_empty(path)?;
        let mut found = cursor::weaknesses(&root);
        if !cursor::in_sync(&root, &plan.cursor) {
            found.push(OUT_OF_DATE.to_owned());
        }
        if lock.is_some_and(|l| path.is_file() && !l.pins(path)) {
            found.push(NOT_PINNED.to_owned());
        }
        Ok(found)
    }

    fn undo(&self) -> Undo {
        Undo::Json(cursor::remove)
    }
}

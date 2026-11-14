//! Cursor's `sandbox.json`.

use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use super::Generated;
use crate::home::Home;
use crate::install::read_or_empty;
use crate::integrity::Lock;
use crate::sandbox::backend::{
    Input, NOT_PINNED, OUT_OF_DATE, Output, Pin, SandboxBackend, Undo, strings,
};
use crate::sandbox::install::{Rendered, parse_json, unavailable};
use crate::sandbox::{Plan, Report};

pub struct CursorSandbox;

/// The backend, as `sandbox::backend_of` names it.
pub static BACKEND: CursorSandbox = CursorSandbox;

impl SandboxBackend for CursorSandbox {
    fn generate(&self, input: &Input<'_>, _settings: &Path) -> Result<Box<dyn Output>> {
        Ok(Box::new(super::generate(input.ir, input.proxy_port)?))
    }

    fn undo(&self) -> Undo {
        Undo::Json(super::remove)
    }

    fn pin(&self) -> Pin {
        Pin::Whole(carries_keys)
    }
}

impl Output for Generated {
    fn render(&self, _home: &Home, host: Host, current: &str) -> Result<Option<Rendered>> {
        if unavailable(host).is_some() {
            return Ok(None);
        }
        let mut root = parse_json(current)?;
        let changed = super::apply(&mut root, self)?;
        Ok(changed.then_some(Rendered {
            text: serde_json::to_string_pretty(&root)? + "\n",
            claude_rules: None,
        }))
    }

    fn report(&self) -> &Report {
        &self.report
    }

    fn shown(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self.settings)?)
    }

    fn problems(
        &self,
        _home: &Home,
        path: &Path,
        _plan: &Plan,
        lock: Option<&Lock>,
    ) -> Result<Vec<String>> {
        let root = read_or_empty(path)?;
        let mut found = super::weaknesses(&root);
        if !super::in_sync(&root, self) {
            found.push(OUT_OF_DATE.to_owned());
        }
        if lock.is_some_and(|l| path.is_file() && !l.pins(path)) {
            found.push(NOT_PINNED.to_owned());
        }
        Ok(found)
    }

    /// `additionalReadwritePaths`.
    fn writable_dirs(&self) -> Vec<String> {
        strings(self.settings.get("additionalReadwritePaths"))
    }
}

/// Whether the file at `path` carries OpenMoat's keys: whether removing them
/// would change it.
fn carries_keys(path: &Path) -> Result<bool> {
    Ok(super::remove(&mut read_or_empty(path)?))
}

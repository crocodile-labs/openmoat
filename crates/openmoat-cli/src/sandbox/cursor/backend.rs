//! Cursor's `sandbox.json`.

use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use crate::home::Home;
use crate::install::read_or_empty;
use crate::integrity::Lock;
use crate::sandbox::backend::{NOT_PINNED, OUT_OF_DATE, Pin, SandboxBackend, Undo};
use crate::sandbox::install::{Rendered, parse_json, unavailable};
use crate::sandbox::{Plan, Report};

pub struct CursorSandbox;

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
        let changed = super::apply(&mut root, &plan.cursor)?;
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
        let mut found = super::weaknesses(&root);
        if !super::in_sync(&root, &plan.cursor) {
            found.push(OUT_OF_DATE.to_owned());
        }
        if lock.is_some_and(|l| path.is_file() && !l.pins(path)) {
            found.push(NOT_PINNED.to_owned());
        }
        Ok(found)
    }

    fn undo(&self) -> Undo {
        Undo::Json(super::remove)
    }

    fn pin(&self) -> Pin {
        Pin::Whole(carries_keys)
    }
}

/// Whether the file at `path` carries OpenMoat's keys: whether removing them
/// would change it.
fn carries_keys(path: &Path) -> Result<bool> {
    Ok(super::remove(&mut read_or_empty(path)?))
}

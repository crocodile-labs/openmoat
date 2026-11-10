//! OpenMoat's permissions profile in Codex's `config.toml`.

use std::path::Path;

use anyhow::{Context as _, Result};
use openmoat_hosts::Host;
use toml_edit::DocumentMut;

use super::PROFILE;
use crate::home::Home;
use crate::integrity::Lock;
use crate::sandbox::backend::{NOT_PINNED, OUT_OF_DATE, Pin, SandboxBackend, Undo};
use crate::sandbox::install::{Rendered, read_toml};
use crate::sandbox::{Plan, Report};

pub struct CodexProfile;

impl SandboxBackend for CodexProfile {
    fn render(
        &self,
        _home: &Home,
        _host: Host,
        plan: &Plan,
        current: &str,
    ) -> Result<Option<Rendered>> {
        let mut doc: DocumentMut = current.parse().context("parsing the settings")?;
        let changed = super::apply(&mut doc, &plan.codex)?;
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
        super::apply(&mut doc, &plan.codex)?;
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
        let mut found = super::weaknesses(&doc, plan.proxy_port.is_some());
        if !super::in_sync(&doc, &plan.codex) {
            found.push(OUT_OF_DATE.to_owned());
        }
        if lock.is_some_and(|l| !l.pins_owned_part(path)) {
            found.push(NOT_PINNED.to_owned());
        }
        Ok(found)
    }

    fn undo(&self) -> Undo {
        Undo::Toml(super::remove)
    }

    fn pin(&self) -> Pin {
        Pin::Part {
            carries: carries_profile,
            digest: profile_digest,
        }
    }
}

/// Whether the config at `path` carries OpenMoat's profile.
fn carries_profile(path: &Path) -> Result<bool> {
    let doc = read_toml(path)?;
    Ok(doc
        .get("permissions")
        .and_then(|p| p.get(PROFILE))
        .is_some())
}

/// SHA-256 of the part of the config at `path` OpenMoat owns ([`super::owned_part`]).
fn profile_digest(path: &Path) -> Result<String> {
    Ok(crate::integrity::sha256_hex(
        super::owned_part(&read_toml(path)?).as_bytes(),
    ))
}

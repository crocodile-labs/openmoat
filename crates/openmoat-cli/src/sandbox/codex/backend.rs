//! OpenMoat's permissions profile in Codex's `config.toml`.

use std::path::Path;

use anyhow::{Context as _, Result};
use openmoat_core::AtomicAction;
use openmoat_core::ir::Effect;
use openmoat_hosts::Host;
use toml_edit::DocumentMut;

use super::{Generated, PROFILE};
use crate::home::Home;
use crate::integrity::Lock;
use crate::sandbox::backend::{Input, NOT_PINNED, OUT_OF_DATE, Output, Pin, SandboxBackend, Undo};
use crate::sandbox::install::{Rendered, read_toml};
use crate::sandbox::{Plan, Report};

pub struct CodexProfile;

/// The backend, as `sandbox::backend_of` names it.
pub static BACKEND: CodexProfile = CodexProfile;

impl SandboxBackend for CodexProfile {
    /// The profile, with the Codex home (`$CODEX_HOME`, the directory of
    /// `config.toml`) denied and the `moat` binary kept from writes. On Linux,
    /// where Codex runs its own executable inside bubblewrap, that executable
    /// is made readable and the names the policy denies anywhere are denied in
    /// the workspace roots too.
    fn generate(&self, input: &Input<'_>, settings: &Path) -> Result<Box<dyn Output>> {
        let mut generated = super::generate(input.ir, input.homes, input.proxy_port)?;
        let codex_home = settings.parent();
        if let Some(codex_home) = codex_home {
            super::protect(&mut generated, codex_home);
        }
        let checker = input.ir.checker()?;
        super::read_only(&mut generated, input.binary_paths, |path| {
            let read = AtomicAction::FsRead {
                path: path.to_owned(),
            };
            checker.check_os(&read) == Some(Effect::Allow)
        });
        if input.linux {
            super::read_own_binary(&mut generated, super::own_binary().as_deref(), codex_home);
            super::deny_names(&mut generated);
        }
        Ok(Box::new(generated))
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

impl Output for Generated {
    fn render(&self, _home: &Home, _host: Host, current: &str) -> Result<Option<Rendered>> {
        let mut doc: DocumentMut = current.parse().context("parsing the settings")?;
        let changed = super::apply(&mut doc, self)?;
        Ok(changed.then_some(Rendered {
            text: doc.to_string(),
            claude_rules: None,
        }))
    }

    fn report(&self) -> &Report {
        &self.report
    }

    fn shown(&self) -> Result<String> {
        let mut doc = DocumentMut::new();
        super::apply(&mut doc, self)?;
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
        if !super::in_sync(&doc, self) {
            found.push(OUT_OF_DATE.to_owned());
        }
        if lock.is_some_and(|l| !l.pins_owned_part(path)) {
            found.push(NOT_PINNED.to_owned());
        }
        Ok(found)
    }

    /// The paths of the profile's `filesystem` table with mode `write`.
    fn writable_dirs(&self) -> Vec<String> {
        let filesystem = self.profile.get("filesystem").and_then(|f| f.as_table());
        filesystem
            .into_iter()
            .flat_map(toml_edit::Table::iter)
            .filter(|(key, mode)| !key.starts_with(':') && mode.as_str() == Some("write"))
            .map(|(key, _)| key.to_owned())
            .collect()
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

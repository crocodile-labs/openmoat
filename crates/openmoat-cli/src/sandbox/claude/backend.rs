//! Claude Code's `sandbox` block and permission rules, in its hook file.

use std::path::Path;

use anyhow::Result;
use openmoat_core::Secret;
use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::Generated;
use super::mask::{self, Mask};
use crate::home::Home;
use crate::install::{Recorded, read_or_empty};
use crate::integrity::Lock;
use crate::sandbox::backend::{
    Input, MaskLevel, OUT_OF_DATE, Output, Pin, SandboxBackend, SecretMask, Undo, strings,
};
use crate::sandbox::install::{Rendered, parse_json, unavailable};
use crate::sandbox::{Plan, Report};

/// Whether Claude Code runs on macOS here, where it applies a `file` mask entry
/// as a read deny (the sandboxing docs, "Mask credential files").
const MASK_FILES_DENIED: bool = cfg!(target_os = "macos");

pub struct ClaudeSettings;

/// The backend, as `sandbox::backend_of` names it.
pub static BACKEND: ClaudeSettings = ClaudeSettings;

impl SandboxBackend for ClaudeSettings {
    fn generate(&self, input: &Input<'_>, settings: &Path) -> Result<Box<dyn Output>> {
        let mut generated = super::generate(input.ir, input.proxy_port, input.linux)?;
        super::protect(&mut generated, settings);
        super::deny_write(&mut generated, input.binary_paths);
        super::deny_edit(&mut generated, input.binary_paths);
        Ok(Box::new(generated))
    }

    fn undo(&self) -> Undo {
        Undo::WithHooks(super::remove)
    }

    fn pin(&self) -> Pin {
        Pin::WithHooks
    }

    fn masks_secrets(&self) -> bool {
        true
    }
}

impl Output for Generated {
    fn render(&self, home: &Home, host: Host, current: &str) -> Result<Option<Rendered>> {
        let mut owned = Recorded::load(home)?.claude_rules;
        let mut root = parse_json(current)?;
        let changed = if unavailable(host).is_some() {
            super::apply_rules(&mut root, self, &mut owned)
        } else {
            super::apply(&mut root, self, &mut owned)
        }?;
        Ok(changed.then_some(Rendered {
            text: serde_json::to_string_pretty(&root)? + "\n",
            claude_rules: Some(owned),
        }))
    }

    fn report(&self) -> &Report {
        &self.report
    }

    fn shown(&self) -> Result<String> {
        let mut doc = json!({});
        super::apply(&mut doc, self, &mut Vec::new())?;
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
        let mut found = super::weaknesses(&root, self.block_reads, plan.proxy_port);
        found.extend(mask::weaknesses(&root, self));
        let owned = Recorded::load(home)?.claude_rules;
        if !super::in_sync(&root, self, &owned) {
            found.push(OUT_OF_DATE.to_owned());
        }
        Ok(found)
    }

    /// `sandbox.filesystem.allowWrite`.
    fn writable_dirs(&self) -> Vec<String> {
        let filesystem = self.sandbox.get("filesystem");
        strings(filesystem.and_then(|f| f.get("allowWrite")))
    }

    fn secret_masks<'a>(&self, settings: &Value, secrets: &'a [Secret]) -> Vec<SecretMask<'a>> {
        mask::states(settings, secrets, &self.report, MASK_FILES_DENIED)
            .into_iter()
            .map(|(secret, state)| SecretMask {
                secret,
                text: state.describe(),
                level: match state {
                    Mask::Active => MaskLevel::Masked,
                    Mask::NotWritten => MaskLevel::NotWritten,
                    Mask::FileDenied | Mask::Skipped(_) => MaskLevel::Unmasked,
                },
            })
            .collect()
    }
}

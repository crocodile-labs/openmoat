//! Claude Code's `sandbox` block and permission rules, in its hook file.

use std::path::Path;

use anyhow::Result;
use openmoat_core::Secret;
use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::mask::{self, Mask};
use crate::home::Home;
use crate::install::{Recorded, read_or_empty};
use crate::integrity::Lock;
use crate::sandbox::backend::{MaskLevel, OUT_OF_DATE, Pin, SandboxBackend, SecretMask, Undo};
use crate::sandbox::install::{Rendered, parse_json, unavailable};
use crate::sandbox::{Plan, Report};

/// Whether Claude Code runs on macOS here, where it applies a `file` mask entry
/// as a read deny (the sandboxing docs, "Mask credential files").
const MASK_FILES_DENIED: bool = cfg!(target_os = "macos");

pub struct ClaudeSettings;

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
            super::apply_rules(&mut root, &plan.claude, &mut owned)
        } else {
            super::apply(&mut root, &plan.claude, &mut owned)
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
        super::apply(&mut doc, &plan.claude, &mut Vec::new())?;
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
        let mut found = super::weaknesses(&root, plan.claude.block_reads, plan.proxy_port);
        found.extend(mask::weaknesses(&root, &plan.claude));
        let owned = Recorded::load(home)?.claude_rules;
        if !super::in_sync(&root, &plan.claude, &owned) {
            found.push(OUT_OF_DATE.to_owned());
        }
        Ok(found)
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

    fn secret_masks<'a>(
        &self,
        settings: &Value,
        secrets: &'a [Secret],
        plan: &Plan,
    ) -> Vec<SecretMask<'a>> {
        mask::states(settings, secrets, &plan.claude.report, MASK_FILES_DENIED)
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

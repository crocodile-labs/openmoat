//! Hook files whose OpenMoat entries sit among the person's own: the layout
//! `{"hooks": {"<event>": [entry, …]}}` that Claude Code, Codex, Cursor,
//! GitHub Copilot CLI, Gemini CLI and, in YAML ([`yaml`]), Hermes Agent share,
//! each with its own entry shape ([`HookFile`]).
//!
//! Pure document work: the CLI reads the file, backs it up and writes it; the
//! code here only edits and inspects the parsed document. Our entries are
//! recognised by the `guard --host <id>` they run, so re-running `init`
//! updates the binary path and matcher in place and never duplicates.
//! Unrelated settings are preserved as JSON values.

use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::HookSpec;

pub(crate) mod nested;
pub mod yaml;

/// How one host's hook file lays out an entry of OpenMoat's.
pub trait HookFile: Sync + std::fmt::Debug {
    /// Whether policy upgrade and sandbox sync should refresh existing
    /// entries of this layout, after the CLI checks the lock and terminal.
    fn refresh_on_upgrade(&self) -> bool {
        false
    }

    /// The entry for `spec` that runs `binary` as `guard --host <id>`; with
    /// `block`, one that asks the host to block the call when the guard fails
    /// (only where [`Self::knows_on_failure`]).
    fn entry(&self, spec: &HookSpec, id: &str, binary: &str, block: bool) -> Value;

    /// Whether `entry` runs OpenMoat's guard for host `id`.
    fn is_ours(&self, entry: &Value, id: &str) -> bool;

    /// The binary one of our entries runs, unquoted from its command.
    fn binary(&self, entry: &Value, id: &str) -> Option<String>;

    /// Whether the layout carries `"version": 1` beside `hooks`.
    fn has_version(&self) -> bool {
        false
    }

    /// Whether an entry can carry `"onFailure": "block"` (Claude Code).
    fn knows_on_failure(&self) -> bool {
        false
    }

    /// The key that must be `true` on each of our entries for the host to
    /// block a call whose hook fails to start, crashes or times out, where the
    /// host runs the call otherwise (Cursor's `failClosed`, Hermes Agent's
    /// `fail_closed`); `None` for a layout without one.
    fn fail_closed_key(&self) -> Option<&'static str> {
        None
    }
}

/// What an edit did to the hook file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HookOutcome {
    /// Every entry was already as it should be.
    Unchanged,
    /// An entry of ours was rewritten.
    Updated,
    /// An entry of ours was added.
    Installed,
}

/// Whether a parsed hook file holds our entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookFileState {
    /// No entry of ours.
    Missing,
    /// Every entry of ours, as it should be.
    Installed,
    /// Present but pointing at a different binary or matcher, or missing one
    /// event; `command` is the binary an entry of ours runs.
    Stale {
        /// The binary the stale entry runs (`?` when it cannot be read).
        command: String,
    },
}

/// A hook file whose shape leaves no place for our entries.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HookFileError {
    /// The document is not a JSON object.
    #[error("{0} is not a JSON object")]
    NotObject(String),
    /// Its `hooks` is not an object.
    #[error("`hooks` in {0} is not an object")]
    HooksNotObject(String),
    /// The list for an event is not an array.
    #[error("`hooks.{event}` in {file} is not an array")]
    EventNotArray {
        /// The event.
        event: &'static str,
        /// The file, as the message names it.
        file: String,
    },
}

impl dyn HookFile {
    /// Add or update our entry for each of `hooks` in `root`, the file `file`
    /// (named in errors). `blocks_on_failure` says whether the host's version
    /// knows `onFailure`; it is asked only when an entry would gain the key.
    ///
    /// # Errors
    /// When `root`, its `hooks` or an event's list has the wrong JSON type.
    pub fn upsert(
        &self,
        root: &mut Value,
        file: &str,
        id: &str,
        hooks: &[HookSpec],
        binary: &str,
        blocks_on_failure: fn() -> bool,
    ) -> Result<HookOutcome, HookFileError> {
        let mut outcome = HookOutcome::Unchanged;
        for spec in hooks {
            outcome =
                outcome.max(self.upsert_one(root, file, id, spec, binary, blocks_on_failure)?);
        }
        Ok(outcome)
    }

    fn upsert_one(
        &self,
        root: &mut Value,
        file: &str,
        id: &str,
        spec: &HookSpec,
        binary: &str,
        blocks_on_failure: fn() -> bool,
    ) -> Result<HookOutcome, HookFileError> {
        let Value::Object(top) = root else {
            return Err(HookFileError::NotObject(file.to_owned()));
        };
        if self.has_version() {
            top.entry("version").or_insert_with(|| json!(1));
        }
        let hooks = top
            .entry("hooks")
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(hooks) = hooks else {
            return Err(HookFileError::HooksNotObject(file.to_owned()));
        };
        let entries = hooks
            .entry(spec.event)
            .or_insert_with(|| Value::Array(Vec::new()));
        let Value::Array(entries) = entries else {
            return Err(HookFileError::EventNotArray {
                event: spec.event,
                file: file.to_owned(),
            });
        };
        let wants_block = spec.block_on_failure && self.knows_on_failure();
        let Some(existing) = entries.iter_mut().find(|e| self.is_ours(e, id)) else {
            let block = wants_block && blocks_on_failure();
            entries.push(self.entry(spec, id, binary, block));
            return Ok(HookOutcome::Installed);
        };
        let desired = self.entry(
            spec,
            id,
            binary,
            self.block(spec, existing, blocks_on_failure),
        );
        if *existing == desired {
            return Ok(HookOutcome::Unchanged);
        }
        *existing = desired;
        Ok(HookOutcome::Updated)
    }

    /// Whether our entry for `spec` carries `"onFailure": "block"`: it does
    /// when it already has the key, so a shell without `claude` on `PATH`
    /// never takes the key away, and otherwise when the host's version knows it.
    fn block(&self, spec: &HookSpec, existing: &Value, blocks_on_failure: fn() -> bool) -> bool {
        self.knows_on_failure()
            && (has_block(existing) || (spec.block_on_failure && blocks_on_failure()))
    }

    /// Whether `root` holds our entry for each of `hooks`, each running
    /// `binary` with the matcher and timeout it should have.
    #[must_use]
    pub fn state(
        &self,
        root: &Value,
        id: &str,
        hooks: &[HookSpec],
        binary: &str,
        blocks_on_failure: fn() -> bool,
    ) -> HookFileState {
        let mut found = 0;
        let mut stale_command = None;
        for spec in hooks {
            match self.ours(root, id, spec) {
                Some(entry)
                    if *entry
                        == self.entry(
                            spec,
                            id,
                            binary,
                            self.block(spec, entry, blocks_on_failure),
                        ) =>
                {
                    found += 1;
                }
                Some(entry) => {
                    stale_command.get_or_insert_with(|| {
                        self.binary(entry, id).unwrap_or_else(|| "?".into())
                    });
                }
                None => {}
            }
        }
        match (found, stale_command) {
            (n, None) if n == hooks.len() => HookFileState::Installed,
            (0, None) => HookFileState::Missing,
            (_, Some(command)) => HookFileState::Stale { command },
            (_, None) => HookFileState::Stale {
                command: binary.to_owned(),
            },
        }
    }

    fn ours<'v>(&self, root: &'v Value, id: &str, spec: &HookSpec) -> Option<&'v Value> {
        root.pointer(&format!("/hooks/{}", spec.event))
            .and_then(Value::as_array)
            .and_then(|entries| entries.iter().find(|e| self.is_ours(e, id)))
    }

    /// Whether one of our entries that should block a call when `moat guard`
    /// fails ([`HookSpec::block_on_failure`]) has no `onFailure`.
    #[must_use]
    pub fn lacks_on_failure(&self, root: &Value, id: &str, hooks: &[HookSpec]) -> bool {
        self.knows_on_failure()
            && hooks
                .iter()
                .filter(|spec| spec.block_on_failure)
                .filter_map(|spec| self.ours(root, id, spec))
                .any(|entry| !has_block(entry))
    }

    /// The [`HookFile::fail_closed_key`] one of our entries in `root` lacks
    /// (absent, or anything but `true`), so the host runs a call whose hook
    /// failed; `None` when every entry has it or the layout has no such key.
    #[must_use]
    pub fn fails_open(&self, root: &Value, id: &str, hooks: &[HookSpec]) -> Option<&'static str> {
        let key = self.fail_closed_key()?;
        hooks
            .iter()
            .filter_map(|spec| self.ours(root, id, spec))
            .any(|entry| entry.get(key) != Some(&Value::Bool(true)))
            .then_some(key)
    }

    /// The inverse of `upsert`: remove every entry of ours, then the
    /// events and `hooks` object that leaves empty, and the `version` when
    /// nothing else remains. Returns whether anything was removed.
    pub fn remove(&self, root: &mut Value, id: &str) -> bool {
        let Value::Object(top) = root else {
            return false;
        };
        let Some(Value::Object(hooks)) = top.get_mut("hooks") else {
            return false;
        };
        let mut removed = false;
        hooks.retain(|_, entries| {
            let Value::Array(list) = entries else {
                return true;
            };
            let before = list.len();
            list.retain(|e| !self.is_ours(e, id));
            removed |= list.len() != before;
            list.len() == before || !list.is_empty()
        });
        if removed && hooks.is_empty() {
            top.remove("hooks");
        }
        if removed && self.has_version() && top.len() == 1 {
            top.retain(|key, value| key != "version" || *value != json!(1));
        }
        removed
    }
}

fn has_block(entry: &Value) -> bool {
    entry.pointer("/hooks/0/onFailure") == Some(&json!("block"))
}

/// ` guard --host <id>`, which every shell-string command of ours ends with.
pub(crate) fn guard_args(id: &str) -> String {
    format!(" guard --host {id}")
}

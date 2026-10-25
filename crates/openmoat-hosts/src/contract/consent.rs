//! A file in which a host records the person's consent to run a hook command
//! ([`super::InstallSpec::consent`]): Hermes Agent runs a shell hook only once
//! its exact command is in `shell-hooks-allowlist.json`, and in its gateway,
//! cron and ACP sessions skips one that is not, without asking.
//!
//! `moat init` is the person's consent: it adds OpenMoat's commands there,
//! `moat uninstall` takes them out, and the lock pins the file with the hook
//! file. Pure document work, like [`crate::HookFile`]: the CLI reads, backs up
//! and writes the file.

use std::fmt::Debug;

use serde_json::Value;

use crate::HookSpec;

/// How a host's consent file records OpenMoat's hook commands.
pub trait ConsentFile: Sync + Debug {
    /// The file's name in the host's configuration directory.
    fn name(&self) -> &'static str;

    /// What the host does with a hook the file does not approve, to follow
    /// its name in `moat status` and `moat doctor`.
    fn without(&self) -> &'static str;

    /// Record consent in `doc` (the file parsed as JSON, `{}` when there is
    /// none) for the command of each of `hooks` that runs `binary` as
    /// `guard --host <id>`, at `now` (an RFC 3339 time), replacing consent to
    /// OpenMoat commands that run another binary; whether that changed `doc`.
    ///
    /// # Errors
    /// `doc` has a shape the host would not read, which is named.
    fn upsert(
        &self,
        doc: &mut Value,
        id: &str,
        hooks: &[HookSpec],
        binary: &str,
        now: &str,
    ) -> Result<bool, String>;

    /// Whether `doc` records consent to the command of each of `hooks`.
    fn holds(&self, doc: &Value, id: &str, hooks: &[HookSpec], binary: &str) -> bool;

    /// Take every OpenMoat command for `id` out of `doc`; whether any was there.
    fn remove(&self, doc: &mut Value, id: &str) -> bool;

    /// Whether `doc` records nothing: what a file `moat init` created holds
    /// once OpenMoat's entries are out.
    fn is_empty(&self, doc: &Value) -> bool;
}

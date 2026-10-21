//! `init` over an existing policy lock with no person at a terminal: a script,
//! CI, or an `openmoat init --yes` detached from the agent that started it,
//! which the parent-process check cannot see. It may repair hooks and re-pin
//! files that did not drift, but not change what the lock trusts: the binary
//! every hook runs, where each agent keeps its files (`hosts.json`, which
//! decides the MCP files the guard reads) and the search path the guard
//! resolves programs by (`environment.json`, which also picks the `git` and
//! `ssh-keygen` OpenMoat runs). New and changed MCP servers are held the same
//! way (`mcp.rs`).

use std::path::Path;

use anyhow::{Result, bail};
use openmoat_hosts::Host;

use crate::home::Home;
use crate::install::{HostConfig, Recorded, other_name};

/// Whether this `init` runs unattended: over an existing lock, with no person.
/// A first install pins what it finds, as it always has.
pub(super) fn applies(lock_existed: bool, person: bool) -> bool {
    lock_existed && !person
}

/// Refuse to point the hooks at `binary` when the lock records another one
/// (`recorded`). The same install's other name (`moat` beside `openmoat`, the
/// rename) is the same binary.
pub(super) fn refuse_other_binary(recorded: &Path, binary: &Path) -> Result<()> {
    if recorded == binary || other_name(recorded).as_deref() == Some(binary) {
        return Ok(());
    }
    bail!(
        "refusing to point the hooks at {} without a person at a terminal: the policy lock \
         records {}; run `openmoat init` in a terminal of your own to change it",
        binary.display(),
        recorded.display()
    )
}

/// `host`'s configuration for this `init`: where this shell's environment puts
/// it ([`HostConfig::for_init`]), or, `unattended`, where `hosts.json` records
/// it ([`HostConfig::for_host`]).
pub(super) fn config(home: &Home, host: Host, unattended: bool) -> Result<HostConfig> {
    if unattended {
        HostConfig::for_host(home, host)
    } else {
        HostConfig::for_init(home, host)
    }
}

/// Record `config`'s directory in `recorded`, unless this `init` is
/// `unattended` and the host is recorded already: then the record stands.
pub(super) fn record(recorded: &mut Recorded, config: &HostConfig, unattended: bool) {
    if unattended && recorded.dir(config.host).is_some() {
        return;
    }
    recorded.insert(config);
}

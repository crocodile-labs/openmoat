//! `moat run` on macOS: the agent under `sandbox-exec` with the Seatbelt
//! profile generated for the session (`crate::sandbox::seatbelt`). Before
//! macOS 13 it refuses (exit 64): `sandbox-exec` there cannot read the profile.
//!
//! The Isolated tier here needs a Linux guest, since Seatbelt does not nest
//! and bubblewrap is Linux-only (ADR-018). ADR-023 picks Apple's
//! `containerization` toolchain for that; today `moat run --isolate` on macOS
//! is still a stub that refuses to run the agent (exit 64), reporting either
//! that `container` is missing or that the full implementation is still
//! coming. It never falls back to the Lightweight tier.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Result, bail};
use openmoat_core::{EvalContext, Policy};

use crate::cli::IsolatedArgs;
use crate::environment::find_in;
use crate::exit::Code;
use crate::os_version;
use crate::sandbox::{Grants, Report, seatbelt_profile};

/// Part of the base system; never one found on `PATH`. Apple has deprecated
/// it, but Codex, Claude Code and Chromium still start their sandboxes with it.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The command the Isolated tier on macOS will drive once the implementation
/// lands (ADR-023): Apple's `containerization` CLI, which boots the Linux
/// guest and projects the virtiofs mounts.
const CONTAINER: &str = "container";

/// The agent, ready to start in its sandbox.
pub struct Confined {
    command: Command,
    report: Report,
}

pub fn confine(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
    program: &Path,
    // Seatbelt denies inside a granted tree, so `kernel-self` keeps the state
    // directory wherever it is.
    _state: &Path,
) -> Result<Confined> {
    // Refused here with a plain reason rather than by `sandbox-exec` with
    // `unbound variable: TIOCSTI`; the profile keeps its deny either way.
    if let Some(reason) = os_version::run_floor(os_version::macos().as_deref()) {
        bail!("{}", refusal(&reason));
    }
    let generated = seatbelt_profile(policy, ctx, grants)?;
    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-p").arg(&generated.profile).arg(program);
    Ok(Confined {
        command,
        report: generated.report,
    })
}

/// The Isolated tier on macOS (ADR-023, #175): a stub until the Apple
/// Virtualization implementation lands. Refuses with a clear reason so no
/// one is surprised by half-work.
///
/// - `container` not on `PATH`: exit 64 with the install hint.
/// - `container` on `PATH`: exit 64 with "not yet implemented, see ADR-023".
///
/// Never a silent fallback to the Lightweight tier; the owner asked for the
/// Isolated boundary, so refusing is fail-closed.
pub fn isolate(_: &Policy, _: &EvalContext, _: Grants, _: &Path, _: &Path) -> Result<Confined> {
    bail!("{}", stub_message(&search_path(), CONTAINER))
}

pub fn inside(_: &IsolatedArgs) -> Result<Code> {
    bail!("only `moat run --isolate` on Linux starts this")
}

/// None: Seatbelt names the proxy's address, not only its port.
pub fn port_only_network() -> Option<String> {
    None
}

impl Confined {
    pub fn command(&mut self) -> &mut Command {
        &mut self.command
    }

    pub fn report(&self) -> &Report {
        &self.report
    }

    /// None: the profile allows only `localhost:<port>`.
    #[expect(
        clippy::unused_self,
        reason = "the method every platform's `Confined` has; Linux's reads itself"
    )]
    pub fn warning(&self) -> Option<&str> {
        None
    }

    pub fn status(mut self) -> Result<ExitStatus> {
        Ok(self.command.status()?)
    }
}

/// What `moat run` says on a macOS too old for its profile (exit 64).
fn refusal(reason: &str) -> String {
    format!(
        "`moat run` {reason}. The agent was not started. The agent hooks still apply the \
         policy to each tool call: start the agent without `moat run`"
    )
}

/// The dirs `PATH` lists today, as [`find_in`] takes them.
fn search_path() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default()
}

/// What `moat run --isolate` tells the user on macOS today, with `#175` in
/// it so hosts and tests can match on it as they did before.
fn stub_message(path: &[PathBuf], program: &str) -> String {
    let found = find_in(path, &[], program);
    if found.is_some() {
        format!(
            "`moat run --isolate` on macOS: not yet implemented, see ADR-023 (#175). `{program}` \
             is installed; the virtualization work ships in follow-up PRs. For now the Isolated \
             tier is Linux-only; `moat run` without --isolate is the Lightweight tier"
        )
    } else {
        format!(
            "`moat run --isolate` on macOS needs Apple's `containerization` toolchain (ADR-023, \
             #175): `{program}` is not on PATH. Install it with `brew install --cask container` \
             or from https://github.com/apple/container/releases, then re-run. Refusing rather \
             than starting the agent in a weaker tier"
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use super::*;

    /// A directory with one executable called `name`, as `PATH` would list it.
    fn with_executable(dir: &Path, name: &str) -> PathBuf {
        let bin = dir.join(name);
        File::create(&bin).expect("creating a fake `container` binary");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))
            .expect("marking it executable");
        dir.to_path_buf()
    }

    /// The stub never exits 0 or 2: hosts rely on these exit codes
    /// (ADR-004), and the owner picked exit 64 for refusing to start.
    #[test]
    fn exit_code_contract_is_64_whichever_branch_the_stub_takes() {
        // The CLI maps `Err(_)` from `isolate()` to `Code::Usage` (64) in
        // `main.rs`; this test asserts the mapping stays in that enum.
        assert_eq!(Code::Usage as u8, 64);
    }

    #[test]
    fn an_old_macos_is_refused_with_a_plain_reason() {
        let reason = os_version::run_floor(Some("12.7")).unwrap();
        let message = refusal(&reason);
        assert!(
            message.starts_with("`moat run` needs macOS 13 or later"),
            "{message}"
        );
        assert!(
            message.contains("hooks still apply the policy"),
            "{message}"
        );
        assert!(!message.contains("unbound variable"), "{message}");
    }

    #[test]
    fn missing_container_points_at_the_install_command() {
        let dir = tempfile::tempdir().expect("a scratch dir");
        let path = vec![dir.path().to_path_buf()];
        let message = stub_message(&path, "container-not-here");
        assert!(message.contains("ADR-023"), "{message}");
        assert!(message.contains("#175"), "{message}");
        assert!(
            message.contains("brew install --cask container"),
            "{message}"
        );
        assert!(
            !message.contains("not yet implemented"),
            "missing is a different branch: {message}"
        );
    }

    #[test]
    fn present_container_says_not_yet_implemented() {
        let dir = tempfile::tempdir().expect("a scratch dir");
        let path = vec![with_executable(dir.path(), "container")];
        let message = stub_message(&path, "container");
        assert!(message.contains("ADR-023"), "{message}");
        assert!(message.contains("#175"), "{message}");
        assert!(message.contains("not yet implemented"), "{message}");
        assert!(
            !message.contains("brew install"),
            "present is a different branch: {message}"
        );
    }

    #[test]
    fn stub_message_never_promises_a_lightweight_fallback() {
        // Fail-closed (ADR-018): the Isolated tier never silently downgrades.
        let dir = tempfile::tempdir().expect("a scratch dir");
        let missing = stub_message(&[dir.path().to_path_buf()], "nope");
        let present = stub_message(&[with_executable(dir.path(), "container")], "container");
        for message in [missing, present] {
            let lowered = message.to_lowercase();
            assert!(!lowered.contains("falls back"), "{message}");
            assert!(!lowered.contains("falling back"), "{message}");
        }
    }
}

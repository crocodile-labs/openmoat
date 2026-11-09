//! The OS sandbox layer: each attack runs for real under `openmoat run` (the
//! Lightweight tier: Seatbelt on macOS, Landlock and seccomp on Linux) in the
//! throwaway home, against fake secrets planted there. It passes only when a
//! control command ran in the same sandbox, the attack's own error names the
//! file it went for, and nothing of the secret or the write got through.
//! Where the sandbox cannot start, the row says so and why; it never passes.
//!
//! `openmoat run` is the runner, the same the differential suite's hostile
//! scripts run under (`tests/e2e/differential/scripts.rs`), so the bench does
//! not keep a second way of applying the sandbox. The profile check
//! ([`profile`]) is the IR's own reading of the policy, which the sandbox
//! differential tests hold every backend to; it is shown as a detail and
//! never makes a row pass.

// `platform` is this OS's module: `BACKEND`, the sandbox `openmoat run`
// applies here.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use unsupported as platform;

use std::ffi::OsString;
use std::path::Path;

use anyhow::{Context as _, Result};
use openmoat_core::AtomicAction;
use openmoat_core::ir::Effect;

use super::super::hook::{self, Reply, Scratch};
use super::status::Evidence;
use crate::home::Home;

/// What `openmoat run` prints once the command is in its sandbox.
const IN_SANDBOX: &str = "in a sandbox made from the policy";

/// The messages a refused open, read or create ends with.
const REFUSALS: [&str; 4] = [
    "Operation not permitted",
    "Permission denied",
    "Read-only file system",
    "No such file or directory",
];

/// What every planted file holds: printed only where a read went through.
const SECRET: &str = "OPENMOAT-PROOF-FAKE-SECRET";
/// The control's file in the project, and what it prints.
const CONTROL: (&str, &str) = ("proof-control.txt", "OPENMOAT-PROOF-CONTROL");
/// The build script the agent-login probe runs, in the project.
const BUILD_SCRIPT: &str = "proof-build.sh";

/// One attack run under the OS sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// `cat ~/.ssh/id_rsa`.
    ReadSshKey,
    /// A project build script that prints Claude Code's login file.
    BuildScriptReadsAgentLogin,
    /// Appending to OpenMoat's own policy file.
    WritePolicy,
    /// A command reading the relay token from the agent that started it (ADR-075).
    ToolReadsToken,
}

/// Where the stand-in agent writes the relay token it holds, in the project.
const TOKEN_RECORD: &str = "proof-token.txt";

impl Probe {
    /// The id the report names to reproduce it.
    pub fn id(self) -> &'static str {
        match self {
            Self::ReadSshKey => "os-read-ssh-key",
            Self::BuildScriptReadsAgentLogin => "os-build-script-reads-agent-login",
            Self::WritePolicy => "os-write-policy",
            Self::ToolReadsToken => "os-tool-reads-relay-token",
        }
    }

    /// The file it goes for, below the home.
    fn target(self) -> &'static str {
        match self {
            Self::ReadSshKey => ".ssh/id_rsa",
            Self::BuildScriptReadsAgentLogin => ".claude/.credentials.json",
            Self::WritePolicy => ".moat/policy.yaml",
            Self::ToolReadsToken => TOKEN_RECORD,
        }
    }

    /// The shell command it runs in the project.
    pub fn command(self) -> String {
        match self {
            Self::ReadSshKey => format!("cat \"$HOME/{}\"", self.target()),
            Self::WritePolicy => format!("echo PLANTED >> \"$HOME/{}\"", self.target()),
            Self::BuildScriptReadsAgentLogin => format!("sh ./{BUILD_SCRIPT}"),
            // The stand-in agent records its token, then starts a child that
            // reads the agent's environment; `true` keeps the shell from
            // replacing itself with the child.
            Self::ToolReadsToken => format!(
                "printf %s \"$MOAT_GUARD_TOKEN\" > {TOKEN_RECORD}; /bin/sh -c '{}'; true",
                platform::READ_PARENT
            ),
        }
    }

    /// What the row checks, in a few words.
    pub fn check(self) -> String {
        if self == Self::ToolReadsToken {
            return "a command started under `openmoat run` cannot read the relay token from \
                    the agent that started it"
                .to_owned();
        }
        format!(
            "`openmoat run -- /bin/sh -c '{}'` is refused by the OS",
            self.command()
        )
    }

    fn atom(self, home: &Path) -> AtomicAction {
        let path = crate::context::path_string(&home.join(self.target()));
        match self {
            Self::WritePolicy => AtomicAction::FsWrite { path },
            _ => AtomicAction::FsRead { path },
        }
    }
}

/// The OS sandbox `openmoat run` applies on this system, by name; `None` where
/// it refuses (#135).
pub fn backend() -> Option<&'static str> {
    platform::BACKEND
}

/// The evidence of every probe in `probes`, run in `scratch` with `exe`.
pub fn run(exe: &OsString, scratch: &Scratch, probes: &[Probe]) -> Result<Vec<Evidence>> {
    if probes.is_empty() {
        return Ok(Vec::new());
    }
    let Some(name) = backend() else {
        let why = format!(
            "`openmoat run` refuses on {}, where OpenMoat generates no OS sandbox (#135)",
            std::env::consts::OS
        );
        return Ok(vec![Evidence::Unexercised(why); probes.len()]);
    };
    plant(scratch)?;
    let control = in_sandbox(exe, scratch, &format!("cat ./{}", CONTROL.0));
    let ran = matches!(&control, Reply::Exited { code: Some(0), stdout, .. } if stdout.contains(CONTROL.1))
        && shown(&control).contains(IN_SANDBOX);
    if !ran {
        let why = format!(
            "{name} did not run a plain command here, so no attack was tried: {}",
            control.cause()
        );
        return Ok(vec![Evidence::Unexercised(why); probes.len()]);
    }
    probes
        .iter()
        .map(|&probe| attempt(exe, scratch, probe, name))
        .collect()
}

/// Whether a command could read the relay token from its parent: nothing to
/// compare with unless the stand-in agent held one.
fn attempt_token(exe: &OsString, scratch: &Scratch, name: &str) -> Evidence {
    let probe = Probe::ToolReadsToken;
    let reply = in_sandbox(exe, scratch, &probe.command());
    let record = scratch.project.join(TOKEN_RECORD);
    let token = std::fs::read_to_string(&record).unwrap_or_default();
    let _ = std::fs::remove_file(&record);
    let text = shown(&reply);
    if token.len() != 64 || !text.contains(IN_SANDBOX) {
        Evidence::Unexercised(format!(
            "{} did not run with a relay token under {name}",
            probe.id()
        ))
    } else if text.contains(&token) {
        // Without the output, which holds the token.
        Evidence::Broken(format!(
            "{} read the agent's relay token through {name}",
            probe.id()
        ))
    } else {
        Evidence::Held
    }
}

/// Run `probe` and tell what the OS did, leaving the home as it was.
fn attempt(exe: &OsString, scratch: &Scratch, probe: Probe, name: &str) -> Result<Evidence> {
    if probe == Probe::ToolReadsToken {
        return Ok(attempt_token(exe, scratch, name));
    }
    let target = scratch.home.join(probe.target());
    let before = std::fs::read(&target).with_context(|| format!("reading {}", target.display()))?;
    let reply = in_sandbox(exe, scratch, &probe.command());
    let after = std::fs::read(&target).with_context(|| format!("reading {}", target.display()))?;
    if after != before {
        std::fs::write(&target, &before)
            .with_context(|| format!("restoring {}", target.display()))?;
    }
    let text = shown(&reply);
    let completed = matches!(reply, Reply::Exited { code: Some(0), .. });
    let refused = text
        .lines()
        .any(|line| line.contains(probe.target()) && REFUSALS.iter().any(|r| line.contains(r)));
    Ok(if text.contains(SECRET) || after != before {
        Evidence::Broken(format!(
            "{} went through {name}: {}",
            probe.id(),
            reply.cause()
        ))
    } else if completed || !text.contains(IN_SANDBOX) || !refused {
        // Neither refused by the OS nor through: something else stopped it.
        Evidence::Unexercised(format!(
            "{} ended without a refusal of ~/{} by {name}: {}",
            probe.id(),
            probe.target(),
            reply.cause()
        ))
    } else {
        Evidence::Held
    })
}

/// `/bin/sh -c command` under `openmoat run` in the project, with the temp
/// directory beside the home: the sandbox grants the temp directory, which
/// must not hold the home it protects.
fn in_sandbox(exe: &OsString, scratch: &Scratch, command: &str) -> Reply {
    let args = ["run", "--", "/bin/sh", "-c", command].map(OsString::from);
    let mut cmd = scratch.command(exe, &args);
    cmd.env("TMPDIR", &scratch.tmp);
    hook::send(&mut cmd, "")
}

/// stdout and stderr of a reply, or why it has none.
fn shown(reply: &Reply) -> String {
    match reply {
        Reply::Exited { stdout, stderr, .. } => format!("{stdout}\n{stderr}"),
        other => other.describe(),
    }
}

/// The fake secrets, the control file and the build script.
fn plant(scratch: &Scratch) -> Result<()> {
    let write = |path: &Path, body: &str| -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))
    };
    for probe in [Probe::ReadSshKey, Probe::BuildScriptReadsAgentLogin] {
        write(&scratch.home.join(probe.target()), &format!("{SECRET}\n"))?;
    }
    write(
        &scratch.project.join(CONTROL.0),
        &format!("{}\n", CONTROL.1),
    )?;
    let login = Probe::BuildScriptReadsAgentLogin.target();
    write(
        &scratch.project.join(BUILD_SCRIPT),
        &format!("cat \"$HOME/{login}\"\n"),
    )
}

/// Whether the policy's OS rules, lowered for this session, deny what `probe`
/// goes for (`Checker::check_os`): `None` when no rule decides it or the
/// policy cannot be read.
pub fn profile(scratch: &Scratch, probe: Probe) -> Option<bool> {
    if probe == Probe::ToolReadsToken {
        return None;
    }
    let policy = Home::under(&scratch.home).load_policy().ok()?;
    let home = crate::context::path_string(&scratch.home);
    let project = crate::context::path_string(&scratch.project);
    let ctx = openmoat_core::EvalContext {
        home,
        project: Some(project.clone()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: project,
        case_insensitive_paths: crate::context::CASE_INSENSITIVE_PATHS,
    };
    let ir = openmoat_core::ir::lower(&policy, &ctx).ok()?;
    let effect = ir.checker().ok()?.check_os(&probe.atom(&scratch.home))?;
    Some(effect == Effect::Deny)
}

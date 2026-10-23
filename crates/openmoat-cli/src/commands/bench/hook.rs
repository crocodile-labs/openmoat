//! Running the hook under test: a throwaway home, an environment that carries
//! nothing of the person's, the payload on stdin and a time limit.

use std::ffi::OsString;
use std::io::{Read, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use openmoat_hosts::Host;

use crate::install::{GUARD_BUDGET_S, dir_variable};
use crate::render;

/// How long the hook may take for one call before it counts as failed: past
/// `openmoat guard`'s own budget, as every host's hook timeout is, so a guard
/// that is slow on a loaded machine (a busy Windows runner can take more than
/// 10 s to start it and wait for the audit log) answers with its own deny
/// instead of being killed half way. The margin matches OpenClaw's plugin (45 s).
pub const TIMEOUT: Duration = Duration::from_secs(GUARD_BUDGET_S + 15);

/// How much of a failed hook's stdout and stderr the bench repeats.
const CAUSE_CHARS: usize = 300;

/// A hook reply larger than this is cut off; no real decision needs more.
const MAX_REPLY_BYTES: u64 = 1024 * 1024;

/// How often [`wait`] checks whether the hook has exited.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// What came back from one run of the hook.
pub enum Reply {
    /// The hook exited; `code` is `None` when a signal ended it.
    Exited {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    },
    /// No exit within [`TIMEOUT`]; the hook was killed.
    TimedOut,
    /// The hook could not be started.
    NotStarted(String),
}

impl Reply {
    /// One line for `--verbose`.
    pub fn describe(&self) -> String {
        match self {
            Self::Exited { code, stdout, .. } => {
                let code = code.map_or_else(|| "killed".to_owned(), |c| c.to_string());
                format!("exit {code}: {}", stdout.trim())
            }
            Self::TimedOut => format!("no exit within {} s", TIMEOUT.as_secs()),
            Self::NotStarted(error) => format!("could not start: {error}"),
        }
    }

    /// Why a host reads this reply as an error, in one line for a mismatch:
    /// the exit code with the start of stdout and stderr, a timeout, or the
    /// start failure.
    pub fn cause(&self) -> String {
        let Self::Exited {
            code,
            stdout,
            stderr,
        } = self
        else {
            return self.describe();
        };
        let code = code.map_or_else(|| "killed".to_owned(), |c| c.to_string());
        let shown = |text: &str| {
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            render::truncate(&render::clean(&text), CAUSE_CHARS)
        };
        format!(
            "exit {code}, stdout {:?}, stderr {:?}",
            shown(stdout),
            shown(stderr)
        )
    }
}

/// A throwaway directory holding the home and the project the hook sees,
/// removed when dropped.
pub struct Scratch {
    root: PathBuf,
    pub home: PathBuf,
    pub project: PathBuf,
}

impl Scratch {
    /// A new directory under the system temporary directory, with the agents'
    /// configuration directories and a git project in its home. `create_dir`
    /// fails on an existing path, so nothing already there is reused.
    pub fn new() -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let root = std::env::temp_dir().join(format!("moat-bench-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&root).with_context(|| format!("creating {}", root.display()))?;
        let home = root.join("home");
        let project = home.join("proj");
        let scratch = Self {
            root,
            home,
            project,
        };
        let mut dirs = vec!["proj/.git"];
        for host in Host::ALL {
            dirs.push(dir_variable(host)?.1);
        }
        for dir in dirs {
            let path = scratch.home.join(dir);
            std::fs::create_dir_all(&path)
                .with_context(|| format!("creating {}", path.display()))?;
        }
        Ok(scratch)
    }

    /// `program` with `args`, run in the project with the environment cleared but
    /// for the search path and the throwaway home (and, on Windows, `SYSTEMROOT`,
    /// without which programs cannot start). No agent configuration variable
    /// (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `MOAT_HOME`, …) and no secret reaches it.
    pub fn command(&self, program: impl Into<OsString>, args: &[OsString]) -> Command {
        let mut cmd = Command::new(program.into());
        cmd.args(args)
            .current_dir(&self.project)
            .env_clear()
            .envs(self.environment());
        cmd
    }

    /// The variables [`Scratch::command`] passes, for `--verbose`.
    pub fn environment(&self) -> Vec<(&'static str, OsString)> {
        let mut vars = vec![
            ("PATH", std::env::var_os("PATH").unwrap_or_default()),
            ("HOME", self.home.clone().into_os_string()),
            ("USERPROFILE", self.home.clone().into_os_string()),
        ];
        if let Some(root) = std::env::var_os("SYSTEMROOT") {
            vars.push(("SYSTEMROOT", root));
        }
        vars
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The program and arguments that run a hook command line the way hosts do:
/// through the system shell.
pub fn shell(command_line: &str) -> (OsString, Vec<OsString>) {
    let (shell, flag) = if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    (shell.into(), vec![flag.into(), command_line.into()])
}

/// Run `cmd` with `payload` on stdin and wait at most [`TIMEOUT`].
pub fn send(cmd: &mut Command, payload: &str) -> Reply {
    let deadline = Instant::now() + TIMEOUT;
    let spawned = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Reply::NotStarted(error.to_string()),
    };
    // Pipes are written and read on threads, so a hook that ignores its input or
    // fills a pipe cannot stall the wait. A hook may exit without reading its
    // input; its reply is what counts.
    if let Some(mut stdin) = child.stdin.take() {
        let payload = payload.to_owned();
        std::thread::spawn(move || stdin.write_all(payload.as_bytes()));
    }
    let stdout = child.stdout.take().map(read_on_thread);
    let stderr = child.stderr.take().map(read_on_thread);
    let Some(status) = wait(&mut child, deadline) else {
        return Reply::TimedOut;
    };
    // A process the hook started may still hold its pipes open: read until the
    // deadline at most.
    let collect = |reader: Option<Receiver<String>>| {
        reader
            .and_then(|r| {
                r.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .ok()
            })
            .unwrap_or_default()
    };
    Reply::Exited {
        code: status.code(),
        stdout: collect(stdout),
        stderr: collect(stderr),
    }
}

/// The exit status once the child exits, or `None` after killing it at `deadline`.
fn wait(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(POLL_INTERVAL);
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn read_on_thread(pipe: impl Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.take(MAX_REPLY_BYTES).read_to_end(&mut bytes);
        let _ = tx.send(String::from_utf8_lossy(&bytes).into_owned());
    });
    rx
}

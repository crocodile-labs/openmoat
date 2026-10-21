//! Running git read-only in the repository a push runs in, within a deadline.
//!
//! Every command only reads: `rev-parse`, `config --get`, `for-each-ref` and
//! `log`. Options that let a repository's config start a program while git
//! reads history are turned off on the command line (an external diff, a
//! text conversion, a signature check, the file system monitor), and git never
//! prompts or pages.

use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Why what a push would publish could not be checked; the push then asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unchecked(pub String);

/// What one git command wrote, up to the limit it was given.
pub struct Out {
    pub bytes: Vec<u8>,
    /// The command exited with status 0. Always false when `cut`.
    pub ok: bool,
    /// The output went past the limit; `bytes` holds the first part.
    pub cut: bool,
}

/// git in one directory, with the time left for the whole check.
pub struct Git {
    /// The `git` the environment snapshot `openmoat init` recorded, by its
    /// absolute path: the hook's own `PATH` may name a directory of the
    /// repository (a relative entry), and this git runs outside any sandbox.
    program: PathBuf,
    dir: PathBuf,
    deadline: Instant,
    budget: Duration,
}

/// Global options for every command, before the subcommand.
const GLOBAL: &[&str] = &[
    "--no-pager",
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.quotePath=false",
    "-c",
    "log.showSignature=false",
];

impl Git {
    /// `program` (git) in `dir`, stopping at `deadline`; `budget` is only for
    /// messages.
    pub fn new(
        program: impl Into<PathBuf>,
        dir: impl Into<PathBuf>,
        deadline: Instant,
        budget: Duration,
    ) -> Self {
        Self {
            program: program.into(),
            dir: dir.into(),
            deadline,
            budget,
        }
    }

    fn timeout(&self) -> Unchecked {
        Unchecked(format!(
            "git did not answer within {} ms",
            self.budget.as_millis()
        ))
    }

    /// Run `git <args>` and read at most `limit` bytes of its output.
    pub fn run(&self, args: &[&str], limit: usize) -> Result<Out, Unchecked> {
        if Instant::now() >= self.deadline {
            return Err(self.timeout());
        }
        let mut child = Command::new(&self.program)
            .args(GLOBAL)
            .args(args)
            .current_dir(&self.dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Unchecked(format!("git could not be started: {e}")))?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            return Err(Unchecked("git's output could not be read".to_owned()));
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let read = stdout.take(limit as u64 + 1).read_to_end(&mut bytes);
            let _ = tx.send(read.map(|_| bytes));
        });
        let left = self.deadline.saturating_duration_since(Instant::now());
        let bytes = match rx.recv_timeout(left) {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Unchecked(format!("git's output could not be read: {e}")));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(self.timeout());
            }
        };
        if bytes.len() > limit {
            let _ = child.kill();
            let _ = child.wait();
            let mut bytes = bytes;
            bytes.truncate(limit);
            return Ok(Out {
                bytes,
                ok: false,
                cut: true,
            });
        }
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Ok(Out {
                        bytes,
                        ok: status.success(),
                        cut: false,
                    });
                }
                Ok(None) if Instant::now() < self.deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(self.timeout());
                }
                Err(e) => return Err(Unchecked(format!("git could not be waited for: {e}"))),
            }
        }
    }

    /// The first line of what `git <args>` prints when it succeeds, `None` when
    /// it fails or prints nothing.
    pub fn value(&self, args: &[&str]) -> Result<Option<String>, Unchecked> {
        let out = self.run(args, 64 * 1024)?;
        if !out.ok {
            return Ok(None);
        }
        let text = String::from_utf8_lossy(&out.bytes);
        Ok(text
            .lines()
            .next()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned))
    }
}

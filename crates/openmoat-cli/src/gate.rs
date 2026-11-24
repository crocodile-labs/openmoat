//! The possession gate on every loosening (ADR-117).
//!
//! The person-only commands refuse to run without a terminal or under an agent
//! (`terminal.rs`). That check answers "is a terminal here and no agent among
//! the ancestors", not "is the person here": a process that gets a command
//! typed into the person's terminal, or started detached under a pseudo-terminal,
//! passes it. Once a person enrols a second factor with `openmoat gate setup`,
//! every command that widens or re-pins the protection also asks for a
//! six-digit code from the person's authenticator app ([`pass`]), after the
//! terminal check; `--yes` never skips it. Without enrolment nothing changes.
//!
//! The shared secret is kept as the audit signing key is (ADR-110): random,
//! written once and owner-only (`home::write_private_new`), refused when others
//! may read or replace it (`key_file::read`), in a file whose name starts with
//! the audit key's so `kernel-self`'s `audit.key*` denies it to agents' reads
//! and its `~/.moat/**` their writes, and the host sandboxes generated from it
//! too. A process with the person's full access outside every hook and sandbox
//! can read it: the factor stops what cannot, not what can (`docs/THREAT_MODEL.md`).
//!
//! Every loosening is recorded in the audit log, enrolled or not, with who ran
//! it, what it changed and whether the factor was asked (`ledger.rs`).

mod ledger;
mod secret;
mod state;
mod totp;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context as _, Result, bail};
use zeroize::Zeroizing;

use crate::home::Home;

pub use ledger::SESSION;
pub use state::{MAX_FAILURES, WINDOW_MS};

/// The secret's file in OpenMoat's state directory. Its name starts with the
/// audit key's, so `kernel-self`'s `audit.key*` denies it to agents.
pub const KEY_FILE: &str = "audit.key.gate";

/// The gate's state file ([`state::State`]).
const STATE_FILE: &str = "gate.json";

/// Debug builds take the clock from `MOAT_GATE_NOW` (Unix seconds) so the
/// end-to-end tests can type a known code, as they type answers under
/// `MOAT_ASSUME_TTY`. Release builds do not contain this check at all.
#[cfg(debug_assertions)]
const NOW_VARIABLE: &str = "MOAT_GATE_NOW";

/// The step a code was taken for in this process: one command that asks more
/// than once (`doctor --accept` accepts hooks and MCP servers too) asks the
/// person once, since a second code in the same 30 seconds would be refused
/// as replayed.
static PASSED: OnceLock<u64> = OnceLock::new();

/// Where the secret of `home` is.
pub fn path(home: &Home) -> PathBuf {
    home.root().join(KEY_FILE)
}

fn state_path(home: &Home) -> PathBuf {
    home.root().join(STATE_FILE)
}

/// Whether a person enrolled the factor: the secret's file is there (whatever
/// it holds; one that cannot be read refuses every loosening).
pub fn enrolled(home: &Home) -> bool {
    std::fs::symlink_metadata(path(home)).is_ok()
}

/// What let a loosening through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Factor {
    /// No factor is enrolled: the terminal check alone, as before ADR-117.
    NotEnrolled,
    /// A code from the enrolled authenticator, for this step.
    Totp(u64),
}

impl Factor {
    fn describe(self) -> String {
        match self {
            Self::NotEnrolled => "possession factor: not enrolled (terminal check only)".to_owned(),
            Self::Totp(step) => format!("possession factor: authenticator code (step {step})"),
        }
    }
}

/// A command the gate let through; [`Pass::record`] writes its ledger row once
/// the change is made.
#[derive(Debug)]
#[must_use = "record the change in the policy-change ledger once it is made"]
pub struct Pass {
    command: String,
    factor: Factor,
}

impl Pass {
    /// What let the command through.
    #[cfg(test)]
    pub fn factor(&self) -> Factor {
        self.factor
    }

    /// Record `what` the command changed, with `details` (each widening it
    /// made, as ADR-111 lists them), in the policy-change ledger.
    pub fn record(self, home: &Home, what: &str, details: &[String]) {
        ledger::change(home, &self.command, self.factor, what, details);
    }
}

/// Let `command`, a loosening a person runs, through: at once when no factor
/// is enrolled; otherwise only with a code from the person's authenticator,
/// typed at the terminal, not used before and within the rate limit. Call it
/// after the terminal check; a refusal is an error (exit 64) and is recorded.
pub fn pass(home: &Home, command: &str) -> Result<Pass> {
    let pass = |factor| Pass {
        command: command.to_owned(),
        factor,
    };
    if !enrolled(home) {
        return Ok(pass(Factor::NotEnrolled));
    }
    if let Some(step) = PASSED.get() {
        return Ok(pass(Factor::Totp(*step)));
    }
    let secret = secret::read(&path(home)).inspect_err(|_| {
        ledger::refused(home, command, "the gate's secret cannot be read");
    })?;
    let step = take(home, command, &secret, now_secs(), || read_code(command))?;
    let _ = PASSED.set(step);
    Ok(pass(Factor::Totp(step)))
}

/// Ask for a code with `typed` and check it against `secret` and the gate's
/// state at `now_secs`; the step it was taken for. Within the rate limit's
/// lock nothing is asked.
fn take(
    home: &Home,
    command: &str,
    secret: &[u8],
    now_secs: u64,
    typed: impl FnOnce() -> Result<Zeroizing<String>>,
) -> Result<u64> {
    let state_path = state_path(home);
    let mut state = state::State::load(&state_path)?;
    let now_ms = i64::try_from(now_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    if let Some(until) = state.locked_until(now_ms) {
        ledger::refused(home, command, "too many wrong codes");
        bail!(
            "refusing `{command}`: {MAX_FAILURES} wrong codes in the last {} minutes. Try again \
             after {} UTC",
            WINDOW_MS / 60_000,
            crate::time::clock(until)
        );
    }
    let typed = typed()?;
    match totp::check(secret, &typed, now_secs, state.last_step) {
        Ok(step) => {
            state.passed(step);
            state.save(&state_path)?;
            Ok(step)
        }
        Err(refusal) => {
            state.failed(now_ms);
            state.save(&state_path)?;
            ledger::refused(home, command, refusal.as_str());
            let hint = match refusal {
                totp::Refusal::Replayed => "wait for the next code and run it again",
                totp::Refusal::Missing | totp::Refusal::Malformed | totp::Refusal::Wrong => {
                    "type the six digits your authenticator app shows for OpenMoat now"
                }
            };
            bail!(
                "refusing `{command}`: {} ({hint}); nothing was changed",
                refusal.as_str()
            )
        }
    }
}

/// The code the person types at the terminal for `command`.
fn read_code(command: &str) -> Result<Zeroizing<String>> {
    eprint!("Code from your authenticator app to confirm `{command}`: ");
    let _ = std::io::stderr().flush();
    let typed = crate::terminal::read_answer().context("reading the code")?;
    Ok(Zeroizing::new(typed.trim().to_owned()))
}

/// The time codes are checked at: the system clock, or in a debug build
/// `MOAT_GATE_NOW`.
fn now_secs() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(secs) = std::env::var(NOW_VARIABLE)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return secs;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// [`now_secs`] in milliseconds, what the rate limit counts in.
fn now_ms() -> i64 {
    i64::try_from(now_secs().saturating_mul(1000)).unwrap_or(i64::MAX)
}

/// What `openmoat gate setup` shows and writes: a new secret, the URI and
/// text an app takes, and, once the person typed a code it gives, the file.
pub struct Enrolment {
    secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Enrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Enrolment { .. }")
    }
}

impl Enrolment {
    /// A new secret, not written anywhere yet.
    pub fn new() -> Result<Self> {
        Ok(Self {
            secret: secret::generate()?,
        })
    }

    /// The `otpauth://` URI, for an app that reads a link or a QR code of it.
    pub fn uri(&self) -> Zeroizing<String> {
        secret::uri(&self.secret)
    }

    /// The secret as text in groups of four, for an app it is typed into.
    pub fn text(&self) -> Zeroizing<String> {
        secret::grouped(&self.secret)
    }

    /// Check `typed` against the new secret (so the app is set up right), then
    /// write the file and start the state at the step it was taken for. Refused
    /// when a secret is there already: replacing it is `gate remove`, which
    /// asks for a code of the old one.
    pub fn confirm(&self, home: &Home, typed: &str) -> Result<()> {
        let step = totp::check(&self.secret, typed, now_secs(), 0)
            .map_err(|refusal| anyhow::Error::msg(refusal.as_str()))
            .context("the code does not match the new secret; nothing was set up")?;
        let path = path(home);
        if !crate::home::write_private_new(&path, secret::encode_file(&self.secret).as_bytes())? {
            bail!(
                "{} is there already: run `openmoat gate remove` first",
                path.display()
            );
        }
        let mut state = state::State::default();
        state.passed(step);
        state.save(&state_path(home))?;
        ledger::change(
            home,
            "openmoat gate setup",
            Factor::Totp(step),
            "possession factor enrolled",
            &[],
        );
        Ok(())
    }
}

/// Remove the enrolled secret and the gate's state: what `openmoat gate
/// remove` does after [`pass`] took a code of it.
pub fn remove(home: &Home) -> Result<()> {
    remove_file(&path(home))?;
    remove_file(&state_path(home))
}

fn remove_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other.with_context(|| format!("removing {}", path.display())),
    }
}

/// The gate's state for `openmoat gate status`: whether it is enrolled, and
/// how many wrong codes count against the limit now.
pub fn status(home: &Home) -> Result<(bool, usize)> {
    let now_ms = now_ms();
    let mut state = state::State::load(&state_path(home))?;
    state.prune(now_ms);
    Ok((enrolled(home), state.failures.len()))
}

#[cfg(test)]
mod tests;

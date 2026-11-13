//! Which tier `openmoat run` starts (ADR-080). On Linux the Isolated tier is
//! the default where bubblewrap can make it; elsewhere, and on Linux with
//! `--no-isolate`, the Lightweight tier. The platform says what it offers
//! ([`Offered`]); this module decides from that, the flags and whether a
//! policy requires the full boundary (ADR-077), and nothing here starts
//! anything, so every case is a unit test on every platform.
//!
//! A run weaker than the default is written to the audit log before the agent
//! starts ([`record`]): the person chose it (`--no-isolate`), or the system
//! could not isolate. A row that cannot be written stops the run.

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Decision, Verdict};

use crate::cli::RunArgs;
use crate::home::Home;
use crate::taint::run::LINK_HOST;

/// The rule of the row a run started with `--no-isolate` writes.
pub const OPTED_OUT_RULE: &str = "run-no-isolate";
/// The rule of the row a run that could not isolate writes.
pub const UNAVAILABLE_RULE: &str = "run-isolation-unavailable";
/// The tool those rows name, beside [`LINK_HOST`]: never a host id, so the
/// run's taint lookup, which reads link rows by their tool, passes them by.
const TOOL: &str = "isolation";

/// What the platform offers for the Isolated tier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(
        dead_code,
        reason = "only Linux offers the Isolated tier; the decision is the same code everywhere"
    )
)]
pub enum Offered {
    /// No Isolated tier to start by default (macOS, Windows): `--isolate` is
    /// refused by the platform itself.
    #[cfg_attr(
        all(target_os = "linux", not(test)),
        expect(
            dead_code,
            reason = "Linux always offers the tier or says why not; only other platforms build this"
        )
    )]
    Not,
    /// bubblewrap can make it here.
    Available,
    /// Linux, where it cannot: why, and how to get it.
    Unavailable(String),
}

/// What the person asked for on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// Neither flag: the platform's default.
    Default,
    /// `--isolate`: the Isolated tier or nothing.
    Isolate,
    /// `--no-isolate`: the Lightweight tier.
    NoIsolate,
}

impl Asked {
    pub fn of(args: &RunArgs) -> Self {
        match (args.tier.isolate, args.tier.no_isolate) {
            (true, _) => Self::Isolate,
            (false, true) => Self::NoIsolate,
            (false, false) => Self::Default,
        }
    }
}

/// The tier this run starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier {
    /// bubblewrap's view of the machine (`linux/isolate.rs`).
    Isolated {
        /// The flag asked for it; otherwise it is the default, and a failure
        /// to build it names `--no-isolate`.
        asked: bool,
    },
    /// Landlock or Seatbelt over the whole machine.
    Lightweight(Lightweight),
}

/// Why the run is the Lightweight tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lightweight {
    /// The platform has no Isolated tier to default to.
    Platform,
    /// `--no-isolate` on a platform that has one.
    OptedOut,
    /// The default could not isolate here: why.
    Unavailable(String),
}

impl Tier {
    pub fn isolated(&self) -> bool {
        matches!(self, Self::Isolated { .. })
    }
}

/// The tier for `asked`, given what the platform `offered` and which policy,
/// if any, requires the full boundary (`strict`). On Linux the full boundary
/// is the Isolated tier, so under it neither a missing bubblewrap nor a flag
/// starts the Lightweight one.
pub fn choose(asked: Asked, offered: &Offered, strict: Option<&str>) -> Result<Tier> {
    Ok(match (asked, offered, strict) {
        // Where it cannot start, the platform refuses with its own reason.
        (Asked::Isolate, _, _) => Tier::Isolated { asked: true },
        (Asked::Default | Asked::NoIsolate, Offered::Not, _) => {
            Tier::Lightweight(Lightweight::Platform)
        }
        (Asked::NoIsolate, _, Some(asks)) => bail!(
            "{asks} requires `openmoat run` to start with its full boundary \
             (`require.run: full-boundary`), which on Linux is the Isolated tier, so \
             `--no-isolate` does not start; no flag lowers this"
        ),
        (Asked::NoIsolate, _, None) => Tier::Lightweight(Lightweight::OptedOut),
        (Asked::Default, Offered::Available, _) => Tier::Isolated { asked: false },
        (Asked::Default, Offered::Unavailable(why), Some(asks)) => bail!(
            "{asks} requires `openmoat run` to start with its full boundary \
             (`require.run: full-boundary`), which on Linux is the Isolated tier, and it \
             cannot start here, so the program does not start: {why}"
        ),
        (Asked::Default, Offered::Unavailable(why), None) => {
            Tier::Lightweight(Lightweight::Unavailable(why.clone()))
        }
    })
}

/// What `openmoat run` prints before the agent starts when the default could
/// not isolate; `None` for every other tier.
pub fn notice(tier: &Tier) -> Option<String> {
    let Tier::Lightweight(Lightweight::Unavailable(why)) = tier else {
        return None;
    };
    Some(format!(
        "moat run: the Isolated tier, `openmoat run`'s default on Linux, cannot start here: \
         {why}. This run is the Lightweight tier and is recorded as such in the audit log; \
         `--no-isolate` chooses it on purpose, `--isolate` refuses to start instead"
    ))
}

/// What a person must add to an error building the default Isolated tier
/// (a grant it refuses, say): the flag that starts the Lightweight tier.
pub fn failed_default(tier: &Tier, strict: bool) -> Option<&'static str> {
    match tier {
        Tier::Isolated { asked: false } if !strict => Some(
            "`openmoat run` starts the Isolated tier by default on Linux, and it did not start; \
             `openmoat run --no-isolate` starts the Lightweight tier instead",
        ),
        _ => None,
    }
}

/// The audit row for a run weaker than the default, if this one is: its
/// rule and reason.
pub fn row(tier: &Tier) -> Option<(&'static str, String)> {
    match tier {
        Tier::Lightweight(Lightweight::OptedOut) => Some((
            OPTED_OUT_RULE,
            "`openmoat run --no-isolate`: the person started the Lightweight tier instead of \
             the Isolated one, so commands could see the rest of the machine the policy's read \
             roots allow, and inside the project the paths the policy denies were covered only \
             as far as `openmoat run` said when it started"
                .to_owned(),
        )),
        Tier::Lightweight(Lightweight::Unavailable(why)) => Some((
            UNAVAILABLE_RULE,
            format!(
                "`openmoat run` could not start the Isolated tier ({why}) and started the \
                 Lightweight tier, so commands could see the rest of the machine the policy's \
                 read roots allow, and inside the project the paths the policy denies were \
                 covered only as far as `openmoat run` said when it started"
            ),
        )),
        Tier::Isolated { .. } | Tier::Lightweight(Lightweight::Platform) => None,
    }
}

/// Write [`row`] for `tier`, if it has one, in the run's audit session
/// `session`. An error stops the run: a weaker run must be on record.
pub fn record(home: &Home, session: &str, cwd: &str, tier: &Tier) -> Result<()> {
    let Some((rule, reason)) = row(tier) else {
        return Ok(());
    };
    write_row(home, (session, cwd), (TOOL, rule), Verdict::Allow, reason)
}

/// The rule of the row a run writes when the person's policy opened the
/// project's top to commands (`sandbox.project_top: writable`, ADR-090).
pub const PROJECT_TOP_RULE: &str = "run-project-top-open";

/// Write that this run granted the project's top whole because the person's
/// policy says `sandbox.project_top: writable` (ADR-090). An error stops the
/// run: the choice must be on record.
pub fn record_project_top(home: &Home, session: &str, cwd: &str) -> Result<()> {
    let reason = "`sandbox.project_top: writable` in the person's policy: `openmoat run` had no \
                  network namespace and granted the project's top whole, so commands could read \
                  `.env` and write `.git/hooks` and `.moat` there"
        .to_owned();
    write_row(
        home,
        (session, cwd),
        (TOOL, PROJECT_TOP_RULE),
        Verdict::Allow,
        reason,
    )
}

/// Write one row of the run's sandbox in its audit session: this module's
/// rows, and the boundary's (`boundary.rs`, ADR-089). `tool` is never a host
/// id, so the run's taint lookup passes the row by.
pub(super) fn write_row(
    home: &Home,
    (session, cwd): (&str, &str),
    (tool, rule): (&str, &str),
    verdict: Verdict,
    reason: String,
) -> Result<()> {
    let decision = Decision::single(verdict, rule, reason);
    let store = Store::open_existing(&home.audit_path())
        .context("opening the audit log to record the run's sandbox")?;
    store.record(&NewEvent {
        host: LINK_HOST,
        session_id: session,
        call_id: None,
        cwd: Some(cwd),
        tool,
        action: None,
        decision: &decision,
        latency_us: 0,
    })?;
    Ok(())
}

/// `openmoat doctor`'s row: which tier a plain `openmoat run` starts here and
/// what applies when it cannot isolate; `None` off Linux. The flag is whether
/// the row is a warning.
pub fn doctor_row(offered: &Offered, strict: Option<&str>) -> Option<(bool, String)> {
    match (offered, strict) {
        (Offered::Not, _) => None,
        (Offered::Available, _) => Some((
            false,
            "openmoat run     starts the Isolated tier (bubblewrap works here); \
             `--no-isolate` starts the Lightweight tier and is recorded in the audit log"
                .to_owned(),
        )),
        (Offered::Unavailable(why), Some(asks)) => Some((
            true,
            format!(
                "openmoat run     refuses to start: {asks} requires the full boundary, which \
                 on Linux is the Isolated tier, and it cannot start here: {why}"
            ),
        )),
        (Offered::Unavailable(why), None) => Some((
            true,
            format!(
                "openmoat run     cannot start the Isolated tier here, so it warns and starts \
                 the Lightweight tier, which shows commands more of the machine and covers less \
                 of the project (another row names what stays open there): {why}"
            ),
        )),
    }
}

#[cfg(test)]
mod tests;

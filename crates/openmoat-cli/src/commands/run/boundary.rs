//! The run's boundary record (ADR-089, `openmoat_core::boundary`): planned
//! from the tier, the network and the kernel before the agent starts,
//! completed with the check of its start, and written to the audit log as
//! one row on every run that starts an agent. `openmoat run --print-boundary`
//! prints the plan and starts nothing.

use anyhow::{Result, bail};
use openmoat_core::boundary::{
    Downgrade, EffectiveBoundary, Landlock, LaunchCheck, Network, NetworkMode, Requested,
    ToolToken, VERSION, Weaker,
};
use openmoat_core::{EvalContext, ProjectTop, Verdict};

use super::isolation::{Asked, Lightweight, Tier, write_row};
use super::{platform, tool_shell};
use crate::cli::{Format, RunArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::sandbox::landlock::abi::{self, Kernel};
use crate::sandbox::own_login::Owner;

/// The rule of the boundary row.
pub const RULE: &str = "run-boundary";

/// The tool the row names: never a host id, so the run's taint lookup,
/// which reads link rows by their tool, passes it by.
const TOOL: &str = "boundary";

/// Why a run with `sandbox.project_top: writable` is weaker (ADR-090).
const PROJECT_TOP_WHY: &str = "`sandbox.project_top: writable` in the person's policy: without a \
     network namespace the project's top is granted whole, so commands can read `.env` and \
     write `.git/hooks` and `.moat` there";

/// What the run knows before the agent starts.
pub struct Plan<'a> {
    pub asked: Asked,
    pub tier: &'a Tier,
    /// Why the network is restricted by port only, where it is.
    pub port_only: Option<String>,
    /// The kernel's Landlock ABI, from the probe (Linux).
    pub kernel: Option<&'a Kernel>,
    pub token: ToolToken,
    pub port: Option<u16>,
    /// The person's policy opened the project's top in this run
    /// (`sandbox.project_top: writable` without a namespace, ADR-090).
    pub project_top_open: bool,
}

/// The record for `plan`, nothing applied or tested yet.
pub fn plan(plan: Plan<'_>) -> EffectiveBoundary {
    let requested = match plan.asked {
        Asked::Default => Requested::Default,
        Asked::Isolate => Requested::Isolated,
        Asked::NoIsolate => Requested::Lightweight,
    };
    let mut downgrades = Vec::new();
    let tier = match plan.tier {
        Tier::Isolated { .. } => openmoat_core::boundary::Tier::Isolated,
        Tier::Lightweight(why) => {
            match why {
                Lightweight::Platform => {}
                Lightweight::OptedOut => downgrades.push(Downgrade {
                    what: Weaker::Tier,
                    chosen: true,
                    why: "`openmoat run --no-isolate`".to_owned(),
                }),
                Lightweight::Unavailable(why) => downgrades.push(Downgrade {
                    what: Weaker::Tier,
                    chosen: false,
                    why: why.clone(),
                }),
            }
            openmoat_core::boundary::Tier::Lightweight
        }
    };
    let mode = match &plan.port_only {
        Some(why) => {
            downgrades.push(Downgrade {
                what: Weaker::Network,
                chosen: false,
                why: why.clone(),
            });
            NetworkMode::PortOnly
        }
        None => platform::NETWORK,
    };
    if plan.project_top_open {
        downgrades.push(Downgrade {
            what: Weaker::ProjectTop,
            chosen: true,
            why: PROJECT_TOP_WHY.to_owned(),
        });
    }
    let landlock = plan.kernel.map(|kernel| match kernel {
        Kernel::Abi(abi) => Landlock {
            abi: Some(*abi),
            unavailable: None,
            enforcement: None,
        },
        Kernel::Missing(why) => Landlock {
            abi: None,
            unavailable: Some(why.clone()),
            enforcement: None,
        },
    });
    EffectiveBoundary {
        version: VERSION,
        os: std::env::consts::OS.to_owned(),
        requested,
        tier,
        downgrades,
        network: Network {
            mode,
            proxy_port: plan.port,
        },
        landlock,
        tool_token: plan.token,
        restrictions: platform::restrictions(
            plan.tier.isolated(),
            plan.port_only.is_some(),
            plan.kernel,
        ),
        launch: None,
    }
}

/// `openmoat run --print-boundary`: the record a run would start with,
/// from the same choices, on standard output as JSON or text; nothing starts.
/// The refusals a run makes before it builds its sandbox are made here too,
/// with the same words and exit: no sandbox on this system, a kernel below
/// Landlock's floor, a port-only network under `--netns=require` or a policy
/// that requires the full boundary (`strict`). Refusals that depend on the
/// generated grants (one over the state directory, a `--write` path holding
/// protected files without a namespace) are found only by a start.
pub fn print_plan(
    (args, home): (&RunArgs, &Home),
    ctx: &EvalContext,
    owner: Owner,
    (tier, strict): (&Tier, Option<&str>),
) -> Result<Code> {
    if let Some(why) = platform::unavailable() {
        bail!("{why}");
    }
    let landlock = platform::landlock();
    if let Some(kernel) = landlock.as_ref().filter(|k| !k.meets_floor()) {
        bail!("{}", abi::summary(kernel));
    }
    let port_only = (!tier.isolated())
        .then(platform::no_network_namespace)
        .flatten();
    super::refuse_port_only(args.netns, strict, port_only.as_deref())?;
    let agent_host = match owner {
        Owner::Agent(host) => Some(host),
        Owner::Unknown => None,
    };
    let roots: Vec<String> = ctx
        .project
        .iter()
        .cloned()
        .chain(args.writes.iter().map(|w| super::resolved(w)))
        .collect();
    let record = plan(Plan {
        asked: Asked::of(args),
        tier,
        port_only: port_only.clone(),
        kernel: landlock.as_ref(),
        token: tool_shell::token(agent_host, tool_shell::would_wrap(&roots)?),
        port: None,
        // Only the Lightweight tier without a namespace reads the setting.
        project_top_open: port_only.is_some()
            && home.load_policy()?.project_top() == ProjectTop::Writable,
    });
    match args.format {
        Format::Json => render::json(&record)?,
        Format::Text => render::boundary::write(&mut std::io::stdout().lock(), &record)?,
    }
    Ok(Code::Ok)
}

/// `--verbose`: the record on standard error before the agent starts.
pub fn show(record: &EffectiveBoundary) -> Result<()> {
    Ok(render::boundary::write(
        &mut std::io::stderr().lock(),
        record,
    )?)
}

/// Once the agent started: fold in `check`, write the row in the run's audit
/// session, and refuse (so the agent is stopped) when a restriction the run
/// asked for is missing or the row cannot be written.
pub fn launched(
    home: &Home,
    (session, cwd): (&str, &str),
    record: &mut EffectiveBoundary,
    check: Option<LaunchCheck>,
) -> Result<()> {
    if let Some(check) = check {
        record.launched(check);
    }
    fail_row_for_test()?;
    let missing = record.missing();
    let verdict = if missing.is_empty() {
        Verdict::Allow
    } else {
        Verdict::Deny
    };
    let json = serde_json::to_string(record)?;
    write_row(home, (session, cwd), (TOOL, RULE), verdict, json)?;
    if !missing.is_empty() {
        bail!(
            "`openmoat run` stopped the agent: what its sandbox promises is not all in force \
             ({}); the audit log has the run's boundary row (`{RULE}`)",
            missing.join("; ")
        );
    }
    Ok(())
}

/// Debug builds only: the row write fails after this many milliseconds, for
/// the end-to-end test that a run whose row cannot be written stops the agent.
const FAIL_ROW_ENV: &str = "MOAT_TEST_FAIL_BOUNDARY_ROW_MS";

/// [`FAIL_ROW_ENV`]'s failure, in a debug build where it is set.
fn fail_row_for_test() -> Result<()> {
    if !cfg!(debug_assertions) {
        return Ok(());
    }
    let Some(ms) = std::env::var(FAIL_ROW_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
    else {
        return Ok(());
    };
    std::thread::sleep(std::time::Duration::from_millis(ms));
    bail!("writing the run's boundary row failed ({FAIL_ROW_ENV}, a test switch)")
}

#[cfg(test)]
mod tests;

//! What `openmoat run` says on standard error before the agent starts: the
//! program, how its network is held and on which port, the audit session,
//! the tier's warnings, and with `--verbose` the sandbox's report.

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;
use openmoat_core::boundary::NetworkMode;

use super::isolation::{self, Tier};
use super::platform;
use super::write_report;
use crate::agent_account::RunAs;
use crate::sandbox::Report;
use crate::sandbox::landlock::abi::{self, Kernel};

/// How the agent's network is held, in the words the first line uses. The
/// tests find the port after "proxy on 127.0.0.1:" in either line, so each
/// ends with the proxy.
fn network(agent: &platform::Confined, port: u16) -> String {
    if agent.agent_account() == RunAs::Filtered {
        "network held by the agent account's Windows Filtering Platform filters to OpenMoat's \
         proxy"
            .to_owned()
    } else if platform::NETWORK == NetworkMode::ProxyVariables {
        "network through OpenMoat's proxy for programs that honour HTTP_PROXY (not held by the \
         OS)"
        .to_owned()
    } else if agent.warning().is_some() {
        format!("network only to port {port} on any host, OpenMoat's proxy")
    } else {
        "network only through OpenMoat's proxy".to_owned()
    }
}

/// What the user must know before the agent starts, on standard error.
pub(super) fn notice(
    program: &Path,
    port: u16,
    session: &str,
    agent: &platform::Confined,
    (tier, landlock, verbose): (&Tier, Option<&Kernel>, bool),
) -> Result<()> {
    let report: &Report = agent.report();
    let mut err = std::io::stderr().lock();
    let sees = if tier.isolated() {
        "; it sees only the project, the read roots and --write paths"
    } else {
        ""
    };
    let network = network(agent, port);
    writeln!(
        err,
        "moat run: {} in a sandbox made from the policy{sees}, {network} on 127.0.0.1:{port} \
         (audit session {session})",
        program.display()
    )?;
    if let Some(warning) = agent.warning() {
        writeln!(err, "{warning}")?;
    }
    if let Some(fallback) = isolation::notice(tier) {
        writeln!(err, "{fallback}")?;
    }
    if let Some(open) = agent.project_notice() {
        writeln!(err, "{open}")?;
    }
    let off = crate::sandbox::install::own_sandbox_off();
    if verbose {
        writeln!(
            err,
            "  proxy: 127.0.0.1:{port}\n  \
             turn the agent's own sandbox off{off}: sandboxes \
             do not nest, so the agent's cannot start in here. This one holds the agent and \
             every command it starts together, so it is less precise per command than the \
             agent's own sandbox."
        )?;
        write_report(&mut err, report)?;
        if let Some(kernel) = landlock {
            writeln!(err, "  {}", abi::summary(kernel))?;
            for line in abi::lines(kernel) {
                writeln!(err, "    {line}")?;
            }
        }
    } else {
        writeln!(
            err,
            "moat run: turn the agent's own sandbox off{off}; \
             sandbox ready ({} stricter, {} wider; --verbose for details)",
            report.losses.len(),
            report.allowances.len()
        )?;
    }
    Ok(())
}

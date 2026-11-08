//! `openmoat bench --report`: the proof report. Each security promise
//! ([`promises::PROMISES`]) is answered per layer that holds it, from evidence
//! gathered in the bench's throwaway home: the policy decision and the host
//! hook from the bench scenarios, the OS sandbox from attacks run under
//! `openmoat run` ([`os`]), the network boundary from the proxy's decision
//! ([`net`]), and a failed hook from [`fails_closed`]. A layer that could not
//! be exercised here is NOT TESTED HERE with the reason, never PASS
//! ([`status::Status::of`]); any FAIL makes the command exit 1 (ADR-065).

mod fails_closed;
mod net;
mod os;
mod promises;
mod render;
mod status;
#[cfg(test)]
mod tests;

use anyhow::Result;
use openmoat_hosts::Host;
use serde::Serialize;

use super::Target;
use super::hook::Scratch;
use crate::cli::BenchFormat;
use crate::exit::Code;
pub use promises::PROMISES;
use status::{Evidence, Layer, Status};

/// Version of the JSON document, its `format` field.
const FORMAT: &str = "openmoat-bench-report-v1";

/// One scenario's run on one host, split by layer: the problems with the
/// kernel's verdict (policy) and with the host's reading of the reply (hook).
pub struct Checked {
    pub scenario: String,
    pub host: Host,
    pub policy: Vec<String>,
    pub hook: Vec<String>,
}

/// One row: one layer of one promise.
#[derive(Serialize)]
struct Row {
    promise: &'static str,
    question: &'static str,
    layer: Layer,
    check: String,
    #[serde(flatten)]
    status: Status,
    /// Scenario or probe ids that reproduce the row.
    reproduce: Vec<String>,
}

#[derive(Serialize)]
struct HostVersion {
    id: &'static str,
    /// The host's program on the search path and its version, if found.
    version: Option<String>,
}

#[derive(Default, Serialize)]
struct Summary {
    pass: usize,
    fail: usize,
    not_tested_here: usize,
}

#[derive(Serialize)]
struct Report {
    format: &'static str,
    generated_at: String,
    openmoat: &'static str,
    os: String,
    /// The OS sandbox `openmoat run` applies here; `None` where it refuses.
    os_sandbox: Option<&'static str>,
    hosts: Vec<HostVersion>,
    rows: Vec<Row>,
    summary: Summary,
}

/// Every scenario id a promise names, for the bench to run.
pub fn scenario_ids() -> impl Iterator<Item = &'static str> {
    PROMISES.iter().flat_map(|p| p.scenarios.iter().copied())
}

/// Gather the OS, network and failure evidence, build the rows, print the
/// report in `format`, and say whether any exercised layer failed.
pub fn report(
    target: &Target,
    scratch: &Scratch,
    hosts: &[Host],
    checked: &[Checked],
    format: BenchFormat,
) -> Result<Code> {
    let Target::OpenMoat { exe, .. } = target else {
        anyhow::bail!("--report checks OpenMoat itself; it does not take --hook");
    };
    let probes: Vec<os::Probe> = PROMISES.iter().filter_map(|p| p.os).collect();
    // The guard and network checks run before the OS probes, which append to
    // the policy file when the sandbox fails to stop them (and restore it).
    let guard = fails_closed::guard(target, scratch, hosts);
    let network = net::run(scratch);
    let os_evidence = os::run(exe, scratch, &probes)?;
    let mut rows = Vec::new();
    for promise in &PROMISES {
        rows.extend(scenario_rows(promise, checked));
        if let Some(probe) = promise.os {
            let at = probes.iter().position(|p| *p == probe);
            let evidence = at.and_then(|i| os_evidence.get(i)).cloned();
            rows.push(Row {
                promise: promise.id,
                question: promise.question,
                layer: Layer::OsSandbox,
                check: probe.check(),
                status: with_profile(
                    Status::of(evidence, "the probe did not run"),
                    os::profile(scratch, probe),
                ),
                reproduce: vec![probe.id().to_owned()],
            });
        }
        if promise.network {
            rows.push(row(
                promise,
                Layer::Network,
                net::check(),
                [network.clone()],
                net::PROBE,
            ));
        }
        if promise.fails_closed {
            let none = "no host was run";
            let check = fails_closed::GUARD_CHECK.to_owned();
            rows.push(row(
                promise,
                Layer::Hook,
                check,
                guard.clone(),
                fails_closed::PROBE,
            ));
            let check = fails_closed::HOST_CHECK.to_owned();
            let status = Status::of(fails_closed::hosts(hosts), none);
            rows.push(Row {
                promise: promise.id,
                question: promise.question,
                layer: Layer::Hook,
                check,
                status,
                reproduce: Vec::new(),
            });
        }
    }
    crate::install::host_version::prefetch(hosts.iter().copied());
    let mut summary = Summary::default();
    for r in &rows {
        *match r.status {
            Status::Pass => &mut summary.pass,
            Status::Fail(_) => &mut summary.fail,
            Status::NotTested(_) => &mut summary.not_tested_here,
        } += 1;
    }
    let report = Report {
        format: FORMAT,
        generated_at: crate::time::rfc3339(crate::time::now_ms()),
        openmoat: crate::VERSION,
        os: crate::os_version::describe(),
        os_sandbox: os::backend(),
        hosts: hosts
            .iter()
            .map(|&h| HostVersion {
                id: h.id(),
                version: crate::install::host_version::reported(h),
            })
            .collect(),
        rows,
        summary,
    };
    match format {
        BenchFormat::Json => crate::render::json(&report)?,
        BenchFormat::Text => render::text(&report)?,
        BenchFormat::Markdown => render::markdown(&report)?,
    }
    Ok(if report.summary.fail > 0 {
        Code::Failed
    } else {
        Code::Ok
    })
}

/// The policy and hook rows of `promise`, from the scenario runs.
fn scenario_rows(promise: &promises::Promise, checked: &[Checked]) -> Vec<Row> {
    if promise.scenarios.is_empty() {
        return Vec::new();
    }
    let runs: Vec<&Checked> = checked
        .iter()
        .filter(|c| promise.scenarios.contains(&c.scenario.as_str()))
        .collect();
    let evidence = |problems: fn(&Checked) -> &Vec<String>| {
        runs.iter()
            .map(|c| match problems(c).as_slice() {
                [] => Evidence::Held,
                list => Evidence::Broken(format!(
                    "{} ({}): {}",
                    c.scenario,
                    c.host.id(),
                    list.join("; ")
                )),
            })
            .collect::<Vec<_>>()
    };
    let ids = || promise.scenarios.iter().map(|s| (*s).to_owned()).collect();
    let none = "none of its scenarios runs on the hosts chosen";
    [
        (Layer::Policy, evidence(|c| &c.policy)),
        (Layer::Hook, evidence(|c| &c.hook)),
    ]
    .into_iter()
    .map(|(layer, evidence)| Row {
        promise: promise.id,
        question: promise.question,
        layer,
        check: promise.hook_check.to_owned(),
        status: Status::of(evidence, none),
        reproduce: ids(),
    })
    .collect()
}

fn row(
    promise: &promises::Promise,
    layer: Layer,
    check: String,
    evidence: impl IntoIterator<Item = Evidence>,
    probe: &str,
) -> Row {
    Row {
        promise: promise.id,
        question: promise.question,
        layer,
        check,
        status: Status::of(evidence, "no host was run"),
        reproduce: vec![probe.to_owned()],
    }
}

/// A not-tested OS row says what the policy's OS rules make of the attack;
/// a pass or a fail is what the OS did, and stays as it is.
fn with_profile(status: Status, denies: Option<bool>) -> Status {
    match (status, denies) {
        (Status::NotTested(why), Some(denies)) => {
            let word = if denies { "deny" } else { "do not deny" };
            Status::NotTested(format!(
                "{why} (the policy's OS rules for this session {word} it; not run)"
            ))
        }
        (status, _) => status,
    }
}

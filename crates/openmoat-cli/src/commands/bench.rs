//! `moat bench`: the `MoatBench` scenarios (`docs/MOATBENCH.md`) sent as each
//! host's own hook payloads to OpenMoat, or to any hook command (`--hook`), in a
//! throwaway home. Scenario commands are never executed; only the hook runs.
//!
//! Against OpenMoat the kernel verdict of each step is read back from the
//! throwaway audit log and checked against the scenario, and the host's reading
//! of the reply must carry that verdict. Against another hook, the reply is
//! classified by the host's hook protocol and compared with the scenario.

mod hook;
mod hosts;
mod scenario;
mod score;
#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::io::{self, Write as _};

use anyhow::{Context as _, Result, ensure};
use openmoat_audit::Store;
use openmoat_core::Verdict;
use openmoat_hosts::Host;
use serde::Serialize;

use crate::cli::{BenchArgs, Format};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use hook::Scratch;
use hosts::{Answer, Place};
use scenario::{Call, Scenario, Step, scenarios};
use score::{Outcome, Run, Scorecard, StepResult};

/// What the scenarios run against.
enum Target {
    /// This `moat`, installed in the throwaway home; verdicts read from its audit log.
    OpenMoat { exe: OsString, audit: Store },
    /// A hook command line, run through the system shell.
    Hook(String),
}

impl Target {
    fn command(&self, scratch: &Scratch, host: Host) -> std::process::Command {
        match self {
            Self::OpenMoat { exe, .. } => {
                let args = ["guard", "--host", host.id()].map(OsString::from);
                scratch.command(exe, &args)
            }
            Self::Hook(line) => {
                let (shell, args) = hook::shell(line);
                scratch.command(shell, &args)
            }
        }
    }
}

#[derive(Serialize)]
struct Report<'a> {
    target: &'a str,
    hosts: Vec<&'static str>,
    #[serde(flatten)]
    scorecard: &'a Scorecard,
    /// Host behaviour when the hook fails, from the documentation; not measured.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hook_failure: Vec<HostFailure>,
}

#[derive(Serialize)]
struct HostFailure {
    host: &'static str,
    behaviour: &'static str,
}

pub fn run(args: &BenchArgs) -> Result<Code> {
    let scenarios = scenarios()?;
    let scratch = Scratch::new()?;
    let hosts: Vec<Host> = args.host.map_or_else(|| Host::ALL.to_vec(), |h| vec![h]);
    let target = match &args.hook {
        Some(line) => Target::Hook(line.clone()),
        None => install(&scratch)?,
    };
    if args.verbose {
        describe(&target, &scratch)?;
    }
    let markers = matches!(target, Target::OpenMoat { .. });
    let mut card = Scorecard::default();
    for (category, scenario) in &scenarios {
        if let Some(issue) = scenario.gap.as_ref().filter(|_| markers) {
            card.note_gap(&scenario.id, issue);
        }
        for &host in &hosts {
            if let Some(result) = run_scenario(&target, &scratch, scenario, host, args.verbose)? {
                card.add(category, &scenario.id, host.id(), result);
            }
        }
    }
    if markers {
        card.check_gaps();
    }
    let hook_failure = match &target {
        Target::OpenMoat { .. } => Vec::new(),
        Target::Hook(_) => hosts
            .iter()
            .map(|&host| HostFailure {
                host: host.id(),
                behaviour: hosts::failure(host),
            })
            .collect(),
    };
    let report = Report {
        target: args.hook.as_deref().unwrap_or("openmoat"),
        hosts: hosts.iter().map(|h| h.id()).collect(),
        scorecard: &card,
        hook_failure,
    };
    match args.format {
        Format::Json => render::json(&report)?,
        Format::Text => print_text(&report)?,
    }
    Ok(Code::Ok)
}

/// `moat init --yes` of this binary in the throwaway home.
fn install(scratch: &Scratch) -> Result<Target> {
    let exe = std::env::current_exe().context("locating the moat binary")?;
    let out = scratch
        .command(&exe, &["init".into(), "--yes".into()])
        .output()
        .context("running moat init in the throwaway home")?;
    ensure!(
        out.status.success(),
        "moat init in the throwaway home failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let path = Home::under(&scratch.home).audit_path();
    let audit =
        Store::open_read_only(&path).with_context(|| format!("opening {}", path.display()))?;
    Ok(Target::OpenMoat {
        exe: exe.into_os_string(),
        audit,
    })
}

/// `--verbose`: what every hook run gets besides its payload.
fn describe(target: &Target, scratch: &Scratch) -> Result<()> {
    let mut err = io::stderr().lock();
    let hook = match target {
        Target::OpenMoat { exe, .. } => format!("{} guard --host <host>", exe.to_string_lossy()),
        Target::Hook(line) => line.clone(),
    };
    writeln!(err, "hook: {hook}")?;
    writeln!(err, "working directory: {}", scratch.project.display())?;
    writeln!(err, "environment (nothing else is passed):")?;
    for (name, value) in scratch.environment() {
        writeln!(err, "  {name}={}", value.to_string_lossy())?;
    }
    writeln!(err, "time limit: {} s per call", hook::TIMEOUT.as_secs())?;
    Ok(())
}

/// Run `scenario` on `host`; `None` when the host has no tool for one of its steps.
fn run_scenario(
    target: &Target,
    scratch: &Scratch,
    scenario: &Scenario,
    host: Host,
    verbose: bool,
) -> Result<Option<Run>> {
    let session = format!("{}@{}", scenario.id, host.id());
    let calls = scenario
        .steps
        .iter()
        .map(Step::call)
        .collect::<Result<Vec<_>>>()?;
    let payloads = calls.iter().enumerate().map(|(i, call)| {
        let call_id = format!("{session}#{i}");
        let at = Place {
            home: &scratch.home,
            project: &scratch.project,
            session: &session,
            call_id: &call_id,
        };
        hosts::payload(host, call, &at)
    });
    let Some(payloads) = payloads.collect::<Option<Vec<_>>>() else {
        return Ok(None);
    };
    let mut answers = Vec::new();
    for (i, (call, payload)) in calls.iter().zip(&payloads).enumerate() {
        let reply = hook::send(&mut target.command(scratch, host), payload);
        if verbose {
            eprintln!("> {session}#{i}\n{payload}\n< {}", reply.describe());
        }
        answers.push(hosts::classify(host, call, &reply));
    }
    let mut problems = Vec::new();
    let verdicts = match target {
        Target::OpenMoat { audit, .. } => {
            recorded(audit, &session, &calls, &answers, host, &mut problems)?
        }
        Target::Hook(_) => answers.iter().map(|&a| (a, None)).collect(),
    };
    Ok(Some(compare(
        scenario,
        host,
        &calls,
        &verdicts,
        problems,
        matches!(target, Target::OpenMoat { .. }),
    )))
}

/// OpenMoat's verdict and rules for each step, from the audit log; a reply the
/// host would read differently from that verdict is a problem.
fn recorded(
    audit: &Store,
    session: &str,
    calls: &[Call],
    answers: &[Answer],
    host: Host,
    problems: &mut Vec<String>,
) -> Result<Vec<(Answer, Option<Vec<String>>)>> {
    let events = audit.session(session)?;
    if events.len() != calls.len() {
        problems.push(format!(
            "{} audit events for {} steps",
            events.len(),
            calls.len()
        ));
        return Ok(answers.iter().map(|&a| (a, None)).collect());
    }
    for (i, ((event, call), answer)) in events.iter().zip(calls).zip(answers).enumerate() {
        let want = hosts::seen(host, call, event.verdict);
        if *answer != want {
            problems.push(format!(
                "step {i}: kernel said {}, host reads {}",
                event.verdict.as_str(),
                answer.word()
            ));
        }
    }
    Ok(events
        .into_iter()
        .map(|e| (e.verdict.into(), Some(e.rules)))
        .collect())
}

/// Compare each step's answer with its expectation. Gap markers name OpenMoat
/// issues, so they apply only to OpenMoat (`markers`).
fn compare(
    scenario: &Scenario,
    host: Host,
    calls: &[Call],
    verdicts: &[(Answer, Option<Vec<String>>)],
    mut problems: Vec<String>,
    markers: bool,
) -> Run {
    let mut known = Vec::new();
    let mut steps = Vec::new();
    for (i, ((step, call), (got, rules))) in
        scenario.steps.iter().zip(calls).zip(verdicts).enumerate()
    {
        // OpenMoat is checked on its kernel verdict; another hook on what the host does.
        let want = if markers {
            step.expect.into()
        } else {
            hosts::seen(host, call, step.expect)
        };
        let ok = got.meets(want);
        let gap = step.gap.as_ref().filter(|_| markers);
        let rules = rules.as_ref();
        match (gap, ok) {
            (Some(issue), false) => known.push(format!(
                "step {i} {issue}: expected {}, got {} {rules:?}",
                want.word(),
                got.word()
            )),
            (Some(issue), true) => problems.push(format!(
                "step {i}: marked as gap {issue} but passes; remove the marker"
            )),
            (None, false) => problems.push(format!(
                "step {i}: expected {}, got {}",
                want.word(),
                got.word()
            )),
            (None, true) => {
                if let (Some(rule), Some(rules)) = (&step.rule, rules)
                    && !rules.contains(rule)
                {
                    problems.push(format!(
                        "step {i}: {} without rule {rule} ({rules:?})",
                        got.word()
                    ));
                }
            }
        }
        steps.push(StepResult {
            got: *got,
            expects_ask: step.expect == Verdict::Ask,
            ok,
            gap: gap.is_some(),
        });
    }
    let outcome = match (
        scenario.gap.as_ref().filter(|_| markers),
        problems.is_empty(),
    ) {
        (_, true) if known.is_empty() => Outcome::Pass,
        (_, true) => Outcome::Gap(known),
        (Some(issue), false) => Outcome::Gap(vec![format!("{issue}: {}", problems.join("; "))]),
        (None, false) => Outcome::Fail(problems),
    };
    Run { steps, outcome }
}

fn print_text(report: &Report<'_>) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "MoatBench mini: {} ({})",
        report.target,
        report.hosts.join(", ")
    )?;
    write!(out, "{}", report.scorecard)?;
    if !report.hook_failure.is_empty() {
        writeln!(
            out,
            "hook failure (host behaviour from docs/THREAT_MODEL.md §5, not tested here):"
        )?;
        for failure in &report.hook_failure {
            writeln!(out, "  {}: {}", failure.host, failure.behaviour)?;
        }
    }
    Ok(())
}

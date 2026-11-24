//! The never-widen check as the commands use it (ADR-111): the evaluation
//! contexts and the bundled cases it decides both policies in, and the text
//! a person reads. `openmoat policy diff --widen`, `policy upgrade`,
//! `openmoat trust`, `policy install` and `policy check-diff` call it.

use std::io::Write;

use anyhow::{Context as _, Result};
use openmoat_core::widen::{self, Effect, Outcome, Probe, Report};
use openmoat_core::{Action, EvalContext, Policy};

use crate::render;

/// Most widenings the text lists; `--format json` of `policy diff` lists all.
const SHOWN: usize = 20;

/// The contexts every comparison is decided in: the conformance suite's
/// (`/Users/me`, project `/p`, names compared with case) and a Linux-style
/// one whose file names compare without case, so a rule that differs only
/// in one spelling of a path is still seen.
pub fn contexts() -> Vec<EvalContext> {
    vec![
        EvalContext {
            home: "/Users/me".into(),
            project: Some("/p".into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: "/p".into(),
            case_insensitive_paths: false,
        },
        EvalContext {
            home: "/home/dev".into(),
            project: Some("/home/dev/src/app".into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: "/home/dev/src/app".into(),
            case_insensitive_paths: true,
        },
    ]
}

/// The bundled `MoatBench` steps as calls: the corpus every comparison decides.
pub fn bundled() -> Result<Vec<Probe>> {
    use crate::commands::bench::scenario::{Call, scenarios};
    let mut out = Vec::new();
    for (_, scenario) in scenarios()? {
        for (n, step) in scenario.steps.iter().enumerate() {
            let action = match step.call()? {
                Call::Shell(command) => Action::Shell { command },
                Call::Read(path) => Action::FsRead { path },
                Call::Write(path) | Call::Edit(path) => Action::FsWrite { path },
                Call::Fetch(url) => Action::Fetch { url },
                Call::Mcp { server, tool, .. } => Action::mcp(format!("mcp__{server}__{tool}")),
            };
            out.push(Probe::fixture(format!("{}#{}", scenario.id, n + 1), action));
        }
    }
    Ok(out)
}

/// [`widen::compare`] over [`contexts`] and [`bundled`] plus `extra`.
pub fn compare(old: &Policy, new: &Policy, extra: &[Probe]) -> Result<Report> {
    let mut corpus = bundled()?;
    corpus.extend_from_slice(extra);
    widen::compare(old, new, &contexts(), &corpus).context("comparing the policies")
}

/// The widenings and unranked settings of `report`, for a person: nothing
/// when there are none.
pub fn write_widenings(out: &mut impl Write, report: &Report, all: bool) -> Result<()> {
    let count = report.widenings.len();
    if count > 0 {
        let verb = if count == 1 { "moves" } else { "move" };
        writeln!(
            out,
            "✖ {} {verb} toward allow:",
            crate::report::count(count, "case")
        )?;
        let shown = if all { count } else { count.min(SHOWN) };
        for w in &report.widenings[..shown] {
            let rules = |r: &[String]| {
                if r.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", r.join(", "))
                }
            };
            render::line(
                out,
                &format!(
                    "    {}: {}{} → {}{}",
                    w.case,
                    w.before.as_str(),
                    rules(&w.before_rules),
                    w.after.as_str(),
                    rules(&w.after_rules)
                ),
            )?;
        }
        if shown < count {
            writeln!(
                out,
                "    … and {} more (`openmoat policy diff --widen --format json` lists them)",
                count - shown
            )?;
        }
    }
    for change in &report.settings {
        let mark = match change.effect {
            Effect::Widens => "✖ widens",
            Effect::Unchecked => "! changed, not ranked: look at it",
            Effect::Narrows => continue,
        };
        render::line(
            out,
            &format!("  {mark}: {}: {}", change.setting, change.what),
        )?;
    }
    Ok(())
}

/// Each widening and each widening or unranked setting of `report`, one line
/// each: what the policy-change ledger records (ADR-117).
pub fn ledger_lines(report: &Report) -> Vec<String> {
    let mut lines: Vec<String> = report
        .widenings
        .iter()
        .map(|w| {
            format!(
                "widens {}: {} ({}) → {} ({})",
                w.case,
                w.before.as_str(),
                w.before_rules.join(", "),
                w.after.as_str(),
                w.after_rules.join(", ")
            )
        })
        .collect();
    for change in &report.settings {
        let mark = match change.effect {
            Effect::Widens => "widens",
            Effect::Unchecked => "changed, not ranked",
            Effect::Narrows => continue,
        };
        lines.push(format!("{mark}: {}: {}", change.setting, change.what));
    }
    lines
}

/// The whole report: widenings, settings, rule changes and what was proven.
pub fn write(out: &mut impl Write, report: &Report, all: bool) -> Result<()> {
    write_widenings(out, report, all)?;
    for change in report
        .settings
        .iter()
        .filter(|c| c.effect == Effect::Narrows)
    {
        render::line(
            out,
            &format!("  narrows: {}: {}", change.setting, change.what),
        )?;
    }
    for rule in &report.rules {
        render::line(
            out,
            &format!("  rule {} ({}): {}", rule.id, rule.list, rule.change),
        )?;
    }
    writeln!(out, "{}", summary(report))?;
    Ok(())
}

/// What was checked how, in two lines.
pub fn summary(report: &Report) -> String {
    let mut proven: Vec<&str> = Vec::new();
    let mut open: Vec<String> = Vec::new();
    for p in &report.proof {
        match &p.outcome {
            Outcome::Proven if !proven.contains(&p.kind) => proven.push(p.kind),
            Outcome::NotProven(why) => {
                open.push(format!("{} (context {}): {why}", p.kind, p.context + 1));
            }
            _ => {}
        }
    }
    proven.retain(|k| {
        !report
            .proof
            .iter()
            .any(|p| p.kind == *k && p.outcome != Outcome::Proven)
    });
    let mut text = format!(
        "Checked over {} cases from fixtures and both policies' rules; proven over every subject \
         for: {}; checked over cases only: {}.",
        report.cases,
        if proven.is_empty() {
            "none".to_owned()
        } else {
            proven.join(", ")
        },
        report.sampled.join(", ")
    );
    for line in open {
        text.push_str("\n  not proven: ");
        text.push_str(&line);
    }
    text
}

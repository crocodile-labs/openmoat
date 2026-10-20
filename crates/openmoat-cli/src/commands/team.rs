//! `moat audit report`: one report over exports from several machines, for the
//! person who tunes the team's policy.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write as _};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{Event, ExportedEvent, Summary};
use openmoat_core::Verdict;
use serde::Serialize;

use crate::approvals::OVERLAY_PREFIX;
use crate::cli::{Format, TeamReportArgs};
use crate::exit::Code;
use crate::render;

/// Entries in each ranked list.
const TOP: usize = 10;
/// Width of an action in the text report.
const ACTION_WIDTH: usize = 60;

#[derive(Serialize)]
struct Source {
    file: String,
    events: u64,
    head: Option<String>,
}

#[derive(Default, Serialize)]
struct Counts {
    allowed: u64,
    deferred: u64,
    asked: u64,
    denied: u64,
}

#[derive(Serialize)]
struct RuleCounts {
    rule: String,
    asked: u64,
    denied: u64,
}

#[derive(Serialize)]
struct ActionCount {
    action: String,
    count: u64,
}

/// An action that asked and that a person also approved with `moat allow`
/// (an allow by an `approved-…` rule): the asking rule may be too broad.
#[derive(Default, Serialize)]
struct Candidate {
    action: String,
    rules: BTreeSet<String>,
    asks: u64,
    approvals: u64,
}

#[derive(Serialize)]
struct TeamReport {
    sources: Vec<Source>,
    summary: Summary,
    by_host: BTreeMap<String, Counts>,
    by_rule: Vec<RuleCounts>,
    top_asks: Vec<ActionCount>,
    top_denies: Vec<ActionCount>,
    false_positive_candidates: Vec<Candidate>,
}

/// Exit 64 when a file cannot be read or does not verify: a report over a
/// tampered export would launder it.
pub fn run(args: &TeamReportArgs) -> Result<Code> {
    let mut sources = Vec::new();
    let mut seen = BTreeSet::new();
    let mut events = Vec::new();
    for file in &args.files {
        let (source, exported) = read_export(file)?;
        sources.push(source);
        // The hash commits to every cell, so equal hashes are the same event
        // (overlapping exports of one machine); count it once.
        for event in exported {
            if seen.insert(event.hash.clone()) {
                events.push(event.to_event()?);
            }
        }
    }
    let report = TeamReport::of(sources, &events);
    match args.format {
        Format::Json => render::json(&report)?,
        Format::Text => text(&report)?,
    }
    Ok(Code::Ok)
}

fn read_export(file: &Path) -> Result<(Source, Vec<ExportedEvent>)> {
    let name = file.display();
    let text = std::fs::read_to_string(file).with_context(|| format!("reading {name}"))?;
    let check = openmoat_audit::verify_export(&text, None);
    if let Some(broken) = check.broken {
        bail!(
            "{name}: line {} does not verify ({}); run `openmoat audit verify` on it",
            broken.line,
            broken.kind.describe()
        );
    }
    let events = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing {name}"))?;
    let source = Source {
        file: name.to_string(),
        events: check.events,
        head: check.head,
    };
    Ok((source, events))
}

impl TeamReport {
    fn of(sources: Vec<Source>, events: &[Event]) -> Self {
        let since_ms = events.iter().map(|e| e.ts_ms).min().unwrap_or(0);
        let mut by_host: BTreeMap<String, Counts> = BTreeMap::new();
        let mut rules: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut asks: BTreeMap<String, u64> = BTreeMap::new();
        let mut denies: BTreeMap<String, u64> = BTreeMap::new();
        let mut candidates: BTreeMap<String, Candidate> = BTreeMap::new();
        for event in events {
            let host = by_host.entry(event.host.clone()).or_default();
            let action = render::describe(event);
            match event.verdict {
                Verdict::Allow => host.allowed += 1,
                Verdict::Defer => host.deferred += 1,
                Verdict::Ask => host.asked += 1,
                // `Deny`, and any verdict added to the core later.
                _ => host.denied += 1,
            }
            for rule in &event.rules {
                let counts = rules.entry(rule.clone()).or_default();
                match event.verdict {
                    Verdict::Allow | Verdict::Defer => {}
                    Verdict::Ask => counts.0 += 1,
                    _ => counts.1 += 1,
                }
            }
            let approved = event.rules.iter().any(|r| r.starts_with(OVERLAY_PREFIX));
            match event.verdict {
                Verdict::Ask => {
                    *asks.entry(action.clone()).or_default() += 1;
                    let candidate = candidates.entry(action).or_default();
                    candidate.asks += 1;
                    candidate.rules.extend(event.rules.iter().cloned());
                }
                Verdict::Allow if approved => candidates.entry(action).or_default().approvals += 1,
                Verdict::Allow | Verdict::Defer => {}
                // `Deny`, and any verdict added to the core later: never a
                // candidate for an allow rule.
                _ => *denies.entry(action).or_default() += 1,
            }
        }
        let mut by_rule: Vec<RuleCounts> = rules
            .into_iter()
            .filter(|(_, (asked, denied))| asked + denied > 0)
            .map(|(rule, (asked, denied))| RuleCounts {
                rule,
                asked,
                denied,
            })
            .collect();
        by_rule.sort_by_key(|r| std::cmp::Reverse(r.asked + r.denied));
        let mut false_positive_candidates: Vec<Candidate> = candidates
            .into_iter()
            .filter(|(_, c)| c.asks > 0 && c.approvals > 0)
            .map(|(action, c)| Candidate { action, ..c })
            .collect();
        false_positive_candidates.sort_by_key(|c| std::cmp::Reverse(c.asks + c.approvals));
        false_positive_candidates.truncate(TOP);
        Self {
            sources,
            summary: Summary::of(since_ms, events),
            by_host,
            by_rule,
            top_asks: ranked(asks),
            top_denies: ranked(denies),
            false_positive_candidates,
        }
    }
}

/// The most frequent actions first; ties in action order.
fn ranked(counts: BTreeMap<String, u64>) -> Vec<ActionCount> {
    let mut ranked: Vec<ActionCount> = counts
        .into_iter()
        .map(|(action, count)| ActionCount { action, count })
        .collect();
    ranked.sort_by_key(|a| std::cmp::Reverse(a.count));
    ranked.truncate(TOP);
    ranked
}

fn text(report: &TeamReport) -> Result<()> {
    render::report(&report.summary, "the first exported event")?;
    let mut out = io::stdout().lock();
    writeln!(out, "exports (verified):")?;
    for source in &report.sources {
        let head = source.head.as_deref().unwrap_or("-");
        writeln!(
            out,
            "  {}  {} events  head {head}",
            source.file, source.events
        )?;
    }
    writeln!(
        out,
        "per host (allowed · left to the agent · asked · denied):"
    )?;
    for (host, c) in &report.by_host {
        let row = format!(
            "  {host:<12} {} · {} · {} · {}",
            c.allowed, c.deferred, c.asked, c.denied
        );
        render::line(&mut out, &row)?;
    }
    if !report.by_rule.is_empty() {
        writeln!(out, "per rule (asked · denied):")?;
        for r in &report.by_rule {
            let row = format!("  {:<20} {} · {}", r.rule, r.asked, r.denied);
            render::line(&mut out, &row)?;
        }
    }
    for (title, list) in [
        ("top asks", &report.top_asks),
        ("top denies", &report.top_denies),
    ] {
        if !list.is_empty() {
            writeln!(out, "{title}:")?;
            for a in list {
                let action = render::truncate(&a.action, ACTION_WIDTH);
                render::line(&mut out, &format!("  {:>5}  {action}", a.count))?;
            }
        }
    }
    if !report.false_positive_candidates.is_empty() {
        writeln!(
            out,
            "false-positive candidates (asked, and approved with `openmoat allow`):"
        )?;
        for c in &report.false_positive_candidates {
            let rules: Vec<&str> = c.rules.iter().map(String::as_str).collect();
            let row = format!(
                "  {} asks, {} approvals  {}  [{}]",
                c.asks,
                c.approvals,
                render::truncate(&c.action, ACTION_WIDTH),
                rules.join(", ")
            );
            render::line(&mut out, &row)?;
        }
    }
    Ok(())
}

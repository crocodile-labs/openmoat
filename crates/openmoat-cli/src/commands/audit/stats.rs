//! `openmoat audit stats`: how much OpenMoat got in the way over a window, from
//! this machine's audit log (`disturbance.rs`). Read-only: it opens the log
//! read-only, reads the hangs file, and sends nothing anywhere.

use std::fmt::Write as _;
use std::io::{self, Write as _};

use anyhow::{Result, bail};
use openmoat_hosts::Host;
use serde::Serialize;

use crate::cli::{Format, StatsArgs};
use crate::disturbance::{self, Disturbance, Figures};
use crate::exit::Code;
use crate::home::Home;
use crate::{render, time};

#[cfg(test)]
mod tests;

/// Version of the JSON document, its `format` field.
const FORMAT: &str = "openmoat-stats-v1";

#[derive(Debug, Serialize)]
struct Window {
    since: String,
    until: String,
    host: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct Stats {
    format: &'static str,
    window: Window,
    #[serde(flatten)]
    figures: Disturbance,
}

pub fn run(args: &StatsArgs) -> Result<Code> {
    let now = time::now_ms();
    let since_ms = time::parse_since(&args.since, now)?;
    let until_ms = match &args.until {
        Some(until) => time::parse_since(until, now)?,
        None => now,
    };
    if until_ms <= since_ms {
        bail!("--until must be later than --since");
    }
    let home = Home::locate()?;
    let store = home.open_audit()?;
    let host = args.host.map(Host::id);
    let events: Vec<_> = store
        .since(since_ms, host)?
        .into_iter()
        .filter(|e| e.ts_ms < until_ms)
        .collect();
    let timeouts: Vec<(Host, u64)> = crate::hangs::per_host(&home.hangs_path(), since_ms, until_ms)
        .into_iter()
        .filter(|(h, _)| args.host.is_none_or(|only| only == *h))
        .collect();
    let stats = Stats {
        format: FORMAT,
        window: Window {
            since: time::rfc3339(since_ms),
            until: time::rfc3339(until_ms),
            host,
        },
        figures: disturbance::of(&events, &timeouts),
    };
    match args.format {
        Format::Json => render::json(&stats)?,
        Format::Text => io::stdout().lock().write_all(text(&stats).as_bytes())?,
    }
    Ok(Code::Ok)
}

/// Microseconds as milliseconds with one decimal.
fn ms(us: u64) -> String {
    format!("{}.{}", us / 1000, us % 1000 / 100)
}

/// One row of the table.
fn row(out: &mut String, name: &str, f: &Figures) {
    let (p50, p95, p99) = f.latency.map_or_else(
        || ("-".to_owned(), "-".to_owned(), "-".to_owned()),
        |l| (ms(l.p50), ms(l.p95), ms(l.p99)),
    );
    let v = &f.verdicts;
    let r = &f.per_100_calls;
    let _ = writeln!(
        out,
        "{name:<22} {:>7} {p50:>7} {p95:>7} {p99:>7} {:>7} {:>6} {:>7} {:>5} {:>11.2} {:>10.2}",
        f.calls, v.allow, v.defer, v.review, v.deny, r.review, r.deny
    );
}

/// The report as text: a table per agent and over all, then each agent's
/// held calls, guard failures and hook-failure facts.
fn text(stats: &Stats) -> String {
    let mut out = String::new();
    let d = &stats.figures;
    let _ = writeln!(
        out,
        "OpenMoat audit stats, {} to {}, from this machine's audit log",
        stats.window.since, stats.window.until
    );
    if d.overall.calls == 0 && d.overall.guard_timeouts == 0 {
        let _ = writeln!(out, "no agent calls in this window");
        return out;
    }
    let _ = writeln!(
        out,
        "{:<22} {:>7} {:>7} {:>7} {:>7} {:>7} {:>6} {:>7} {:>5} {:>11} {:>10}",
        "agent",
        "calls",
        "p50 ms",
        "p95 ms",
        "p99 ms",
        "allow",
        "defer",
        "review",
        "deny",
        "reviews/100",
        "denies/100"
    );
    for agent in &d.agents {
        row(&mut out, agent.name, &agent.figures);
    }
    if d.agents.len() > 1 {
        row(&mut out, "all agents", &d.overall);
    }
    for agent in &d.agents {
        let f = &agent.figures;
        let h = &agent.hook_failure;
        let limit = h
            .timeout_s
            .map_or_else(String::new, |s| format!(" (after {s} s)"));
        let _ = writeln!(
            out,
            "{}: {} approved by you; later allowed in the same session: {} denies, {} reviews; \
             guard failures: {} kernel-error, {} with no decision within {} s\n  \
             if the hook fails, the agent {}; if it times out{limit}, it {} (from its spec, \
             not measured)",
            agent.name,
            f.approved,
            f.denies_later_allowed,
            f.reviews_later_allowed,
            f.kernel_errors,
            f.guard_timeouts,
            h.deadline_s,
            h.fails,
            h.times_out,
        );
    }
    if d.other_rows > 0 {
        let _ = writeln!(
            out,
            "{} rows that are not an agent's tool call (proxy, run, approval, delivery) not counted",
            d.other_rows
        );
    }
    out
}

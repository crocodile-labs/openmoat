//! `openmoat watch`: the agents' calls as they happen, one line each, for a
//! second terminal pane (ADR-059).
//!
//! It reads the audit log through a read-only handle and looks for new rows
//! twice a second: one short read by row id each time, which in SQLite's WAL
//! mode never waits on the guard writing nor makes it wait, and no lock is
//! held between looks. Ctrl-C ends it with exit 0.

use std::io::{self, IsTerminal as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result};
use openmoat_audit::{Event, Store};
use openmoat_core::{Policy, Verdict};
use openmoat_hosts::Host;

use crate::VERSION;
use crate::cli::{Only, WatchArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::report::{Paths, Style};

mod row;
#[cfg(test)]
mod tests;

use row::View;

/// How long to wait between looks at the audit log.
const POLL: Duration = Duration::from_millis(500);

/// How often a wait checks for Ctrl-C.
const TICK: Duration = Duration::from_millis(50);

/// The most rows read in one look; the rest are read on the next.
const PAGE: usize = 500;

/// How far back the earlier calls are looked for among the newest rows.
const SCAN: usize = 5_000;

/// The width when the terminal's is not known (`COLUMNS` unset).
const DEFAULT_WIDTH: usize = 100;

pub fn run(args: &WatchArgs) -> Result<Code> {
    let home = Home::locate()?;
    let store = home.open_audit()?;
    let policy = home.load_policy().ok();
    let terminal = io::stdout().is_terminal();
    let view = View {
        style: Style::detect(),
        width: terminal.then(width),
        paths: Paths::detect(),
        policy: policy.as_ref(),
    };
    let filter = Filter::of(args);
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))
        .context("stopping on Ctrl-C")?;

    let mut out = io::stdout().lock();
    writeln!(out, "{}", view.style.bold(&header(&home, policy.as_ref())))?;
    writeln!(out)?;
    let mut last = store.latest_id()?;
    for event in earlier(&store, &filter, args.recent)? {
        print(&mut out, &event, &view)?;
    }
    out.flush()?;
    if args.no_follow {
        return Ok(Code::Ok);
    }
    loop {
        if wait(&stop) {
            return Ok(Code::Ok);
        }
        for event in store.after(last, PAGE)? {
            last = Some(event.id);
            if filter.keeps(&event) {
                print(&mut out, &event, &view)?;
            }
        }
        out.flush()?;
    }
}

/// `true` once Ctrl-C was pressed, else after [`POLL`].
fn wait(stop: &AtomicBool) -> bool {
    let mut waited = Duration::ZERO;
    while waited < POLL {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        std::thread::sleep(TICK);
        waited += TICK;
    }
    stop.load(Ordering::Relaxed)
}

fn print(out: &mut impl io::Write, event: &Event, view: &View<'_>) -> io::Result<()> {
    for line in row::rows(event, view) {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// The newest `count` events `filter` keeps, oldest first.
fn earlier(store: &Store, filter: &Filter, count: usize) -> Result<Vec<Event>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut kept: Vec<Event> = store
        .recent(SCAN)?
        .into_iter()
        .filter(|e| filter.keeps(e))
        .take(count)
        .collect();
    kept.reverse();
    Ok(kept)
}

/// The terminal's width as the shell exports it, else [`DEFAULT_WIDTH`].
fn width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.trim().parse().ok())
        .filter(|w| *w > 0)
        .unwrap_or(DEFAULT_WIDTH)
}

/// `OpenMoat 0.16.0 · watching Claude Code, Codex · policy 16 deny · 20 allow · 12 review`.
fn header(home: &Home, policy: Option<&Policy>) -> String {
    let agents = set_up(home);
    let watching = if agents.is_empty() {
        "watching the audit log".to_owned()
    } else {
        format!("watching {}", agents.join(", "))
    };
    let rules = policy.map(|p| {
        let (deny, allow, review) = p.rule_count();
        format!(" · policy {deny} deny · {allow} allow · {review} review")
    });
    format!(
        "OpenMoat {VERSION} · {watching}{}",
        rules.unwrap_or_default()
    )
}

/// The agents OpenMoat's hook is set up in, by name.
fn set_up(home: &Home) -> Vec<&'static str> {
    let Ok(binary) = crate::install::hook_binary() else {
        return Vec::new();
    };
    Host::ALL
        .into_iter()
        .filter(|host| {
            crate::install::HostConfig::for_host(home, *host).is_ok_and(|c| c.set_up(&binary))
        })
        .map(Host::display_name)
        .collect()
}

/// Which events to show.
struct Filter {
    host: Option<&'static str>,
    verdict: Option<Verdict>,
    /// As the audit log stores it, masked.
    session: Option<String>,
}

impl Filter {
    fn of(args: &WatchArgs) -> Self {
        Self {
            host: args.host.map(Host::id),
            verdict: args.only.map(|only| match only {
                Only::Deny => Verdict::Deny,
                Only::Review => Verdict::Review,
            }),
            session: args.session.as_deref().map(openmoat_audit::redact),
        }
    }

    fn keeps(&self, event: &Event) -> bool {
        self.host.is_none_or(|h| event.host == h)
            && self.verdict.is_none_or(|v| event.verdict == v)
            && self.session.as_ref().is_none_or(|s| &event.session_id == s)
    }
}

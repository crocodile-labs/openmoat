//! Human and machine output.

use std::borrow::Cow;
use std::io::{self, Write};

use anyhow::Result;
use openmoat_audit::{Event, SessionSummary, Summary};
use openmoat_core::{Action, Decision, Verdict};
use serde::Serialize;

use crate::time::{clock, timestamp};

/// Column widths that keep `show` and `replay` rows on one 100-column line.
const RULES_WIDTH: usize = 14;
const TABLE_ACTION_WIDTH: usize = 70;
const REPLAY_ACTION_WIDTH: usize = 52;

#[derive(Serialize)]
struct DecisionReport<'a> {
    verdict: Verdict,
    rules: &'a [String],
    reasons: &'a [String],
    context: &'a [String],
}

/// Pretty JSON on stdout, one document per call, for `--format json`.
/// Standard output for commands that change state (`init`, `allow`, `doctor`).
///
/// A failed write is remembered rather than returned, so a reader that closes
/// the pipe early (`moat init | head -1`) cannot stop the command between
/// saving a file and re-pinning the lock. [`Deferred::finish`] reports the
/// failure once the work is done, and `main` turns a broken pipe into exit 0.
#[derive(Default)]
pub struct Deferred {
    error: Option<io::Error>,
    /// Discard everything: the command prints one JSON document instead.
    quiet: bool,
}

impl Deferred {
    /// A `Deferred` that writes nothing, for a command's `--format json`.
    pub fn quiet() -> Self {
        Self {
            error: None,
            quiet: true,
        }
    }

    /// The first write error, if any, now that the command has done its work.
    pub fn finish(mut self) -> Result<()> {
        self.flush()?;
        match self.error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
}

impl Write for Deferred {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.quiet
            && self.error.is_none()
            && let Err(error) = io::stdout().write_all(buf)
        {
            self.error = Some(error);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.quiet
            && self.error.is_none()
            && let Err(error) = io::stdout().flush()
        {
            self.error = Some(error);
        }
        Ok(())
    }
}

pub fn json<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

/// One compact JSON document per line, for exports a script reads line by line.
pub fn json_lines<T: Serialize>(values: &[T]) -> Result<()> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for value in values {
        serde_json::to_writer(&mut out, value)?;
        writeln!(out)?;
    }
    out.flush()?;
    Ok(())
}

/// A decision as `policy check --format json` reports it: `context` is always
/// present so scripts need not special-case it.
pub fn decision_json(decision: &Decision) -> Result<()> {
    json(&DecisionReport {
        verdict: decision.verdict,
        rules: &decision.rules,
        reasons: &decision.reasons,
        context: &decision.context,
    })
}

pub fn decision_text(decision: &Decision) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{}", verdict_mark(decision.verdict))?;
    line(
        &mut out,
        &format!("   rules : {}", decision.rules.join(" · ")),
    )?;
    for reason in &decision.reasons {
        line(&mut out, &format!("   reason: {reason}"))?;
    }
    for also in &decision.context {
        line(&mut out, &format!("   also  : {also}"))?;
    }
    Ok(())
}

/// One example call of `moat demo` and what the policy decides for it.
#[derive(Debug, Serialize)]
pub struct DemoRow {
    /// What the example shows (`reading a private key`).
    pub shows: &'static str,
    /// The shell command an agent would send.
    pub command: &'static str,
    pub verdict: Verdict,
    /// The rule ids that decided it, comma-separated.
    pub rules: String,
    /// The first reason.
    pub reason: String,
}

/// Width of the command column of `moat demo`.
const DEMO_COMMAND_WIDTH: usize = 48;

/// The `moat demo` table: a row per example, its reason indented below it.
pub fn demo(rows: &[DemoRow], source: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    line(
        &mut out,
        &format!("What OpenMoat decides for these agent calls, with {source}."),
    )?;
    writeln!(
        out,
        "Nothing is run, changed or written.\n\n{:<DEMO_COMMAND_WIDTH$} {:<9} rule",
        "command", "verdict"
    )?;
    for row in rows {
        line(
            &mut out,
            &format!(
                "{:<DEMO_COMMAND_WIDTH$} {:<9} {}",
                truncate(row.command, DEMO_COMMAND_WIDTH),
                verdict_mark(row.verdict),
                row.rules
            ),
        )?;
        line(
            &mut out,
            &truncate(&format!("    {}: {}", row.shows, row.reason), 100),
        )?;
    }
    writeln!(
        out,
        "\nTry any command: openmoat policy check \"<command>\""
    )?;
    Ok(())
}

pub fn event_table(events: &[Event]) -> Result<()> {
    let mut out = io::stdout().lock();
    if events.is_empty() {
        writeln!(out, "no events")?;
        return Ok(());
    }
    writeln!(
        out,
        "id     time (UTC) host         verdict rules          action"
    )?;
    for event in events {
        let row = format!(
            "{:<6} {:<10} {:<12} {:<7} {:<14} {}",
            event.id,
            clock(event.ts_ms),
            event.host,
            event.verdict.as_str(),
            truncate(&event.rules.join(","), RULES_WIDTH),
            truncate(&describe(event), TABLE_ACTION_WIDTH),
        );
        line(&mut out, &row)?;
    }
    Ok(())
}

/// One block per session: header, then a tree of decisions.
pub fn replay(sessions: &[SessionSummary]) -> Result<()> {
    let mut out = io::stdout().lock();
    if sessions.is_empty() {
        writeln!(out, "no sessions in this window")?;
        return Ok(());
    }
    for (i, session) in sessions.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        let header = format!(
            "{} UTC  {}  {}  {}  {} decisions ({} denied, {} asked)",
            clock(session.first_ms),
            session.session_id,
            session.host,
            session.cwd.as_deref().unwrap_or("-"),
            session.events.len(),
            session.count(Verdict::Deny),
            session.count(Verdict::Ask),
        );
        line(&mut out, &header)?;
        let last = session.events.len().saturating_sub(1);
        for (n, event) in session.events.iter().enumerate() {
            let branch = if n == last { "└─" } else { "├─" };
            let kind = event.action.as_ref().map_or("tool", kind_of);
            let row = format!(
                "  {branch} {:<8} {:<52} {} {}",
                kind,
                truncate(&describe(event), REPLAY_ACTION_WIDTH),
                verdict_glyph(event.verdict),
                event.rules.join(", "),
            );
            line(&mut out, &row)?;
        }
    }
    Ok(())
}

pub fn report(summary: &Summary, window: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "since {window} ({}): {} decisions in {} sessions — {} allowed, {} left to the agent, \
         {} asked, {} denied",
        timestamp(summary.since_ms),
        summary.total,
        summary.sessions,
        summary.allowed,
        summary.deferred,
        summary.asked,
        summary.denied,
    )?;
    let centi = summary.asks_per_active_hour_centi();
    writeln!(
        out,
        "asks per active hour: {}.{:02}  ({} active hours)",
        centi / 100,
        centi % 100,
        summary.active_hours
    )?;
    if !summary.by_host.is_empty() {
        let hosts: Vec<String> = summary
            .by_host
            .iter()
            .map(|(h, n)| format!("{h} {n}"))
            .collect();
        line(&mut out, &format!("hosts: {}", hosts.join(" · ")))?;
    }
    if !summary.top_rules.is_empty() {
        writeln!(out, "top rules (ask + deny):")?;
        for (rule, n) in &summary.top_rules {
            line(&mut out, &format!("  {n:>5}  {rule}"))?;
        }
    }
    Ok(())
}

fn verdict_glyph(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "✔",
        Verdict::Defer => "→",
        Verdict::Ask => "❓",
        // `Deny`, and any verdict added to the core later.
        _ => "⛔",
    }
}

fn kind_of(action: &Action) -> &'static str {
    match action {
        Action::Shell { .. } | Action::ForeignShell { .. } => "shell",
        Action::FsRead { .. } | Action::ReadFiles { .. } => "fs.read",
        Action::FsWrite { .. } | Action::Patch { .. } => "fs.write",
        Action::Net { .. } => "net",
        Action::Fetch { .. } => "fetch",
        Action::McpTool { .. } => "mcp",
        _ => "other",
    }
}

pub fn event_detail(event: &Event) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{}  event {}", verdict_mark(event.verdict), event.id)?;
    writeln!(out, "   when    : {}", timestamp(event.ts_ms))?;
    let host = format!("   host    : {}  session {}", event.host, event.session_id);
    line(&mut out, &host)?;
    if let Some(call) = &event.call_id {
        line(&mut out, &format!("   call    : {call}"))?;
    }
    if let Some(cwd) = &event.cwd {
        line(&mut out, &format!("   cwd     : {cwd}"))?;
    }
    line(&mut out, &format!("   tool    : {}", event.tool))?;
    line(&mut out, &format!("   action  : {}", describe(event)))?;
    line(
        &mut out,
        &format!("   rules   : {}", event.rules.join(" · ")),
    )?;
    for reason in &event.reasons {
        line(&mut out, &format!("   reason  : {reason}"))?;
    }
    writeln!(out, "   latency : {} µs", event.latency_us)?;
    Ok(())
}

fn verdict_mark(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "✔ allow",
        Verdict::Defer => "→ defer",
        Verdict::Ask => "❓ ask",
        Verdict::Deny => "⛔ deny",
        _ => "⛔ unknown",
    }
}

pub fn describe(event: &Event) -> String {
    if event.action_unreadable {
        return format!("{} (action unreadable)", event.tool);
    }
    let tool = &event.tool;
    match event.action.as_ref() {
        Some(Action::Shell { command }) => command.clone(),
        Some(Action::ForeignShell { shell, command }) => format!("{shell}: {command}"),
        Some(Action::FsRead { path }) => format!("read {path}"),
        Some(Action::FsWrite { path }) => format!("write {path}"),
        Some(Action::Net { url }) => format!("net {url}"),
        Some(Action::Fetch { url }) => format!("fetch {url}"),
        Some(Action::Patch { writes }) => format!("patch {}", writes.join(", ")),
        Some(Action::ReadFiles { paths }) => format!("read {}", paths.join(", ")),
        Some(Action::McpTool { name, .. }) => name.clone(),
        Some(_) => tool.clone(),
        None => format!("{tool} (ungoverned)"),
    }
}

/// `text` with every control character (C0, DEL and C1) shown as `?`.
///
/// Commands, paths, reasons and ids come from what an agent sent; written raw,
/// an escape sequence in one could set the terminal title or write the
/// clipboard (OSC 52) when a person reads it. One character stays one, so
/// column widths hold.
pub fn clean(text: &str) -> Cow<'_, str> {
    if text.chars().any(char::is_control) {
        Cow::Owned(
            text.chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

/// One line of human output that may hold agent text, cleaned whole: a
/// newline inside a field cannot start a row of its own.
pub fn line(out: &mut impl Write, text: &str) -> io::Result<()> {
    writeln!(out, "{}", clean(text))
}

pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let cut: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_keeps_width() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("a very long command line", 10), "a very lo…");
    }

    #[test]
    fn control_characters_become_question_marks() {
        assert!(matches!(clean("git status ✔"), Cow::Borrowed(_)));
        assert_eq!(
            clean("ls\x1b]0;title\x07\r\n\t\x7f\u{9b}2J"),
            "ls?]0;title??????2J"
        );
    }
}

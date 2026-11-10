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

/// Unchanged lines around each change in the diffs shown before a file is
/// written, as `diff -u` shows them.
pub const DIFF_CONTEXT_LINES: usize = 3;

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
    /// What a test's `Deferred` was given, kept instead of printed.
    #[cfg(test)]
    captured: Option<Vec<u8>>,
}

impl Deferred {
    /// A `Deferred` that writes nothing, for a command's `--format json`.
    pub fn quiet() -> Self {
        Self {
            quiet: true,
            ..Self::default()
        }
    }

    /// A `Deferred` that keeps what it is given, for a test to read.
    #[cfg(test)]
    pub fn capturing() -> Self {
        Self {
            quiet: true,
            captured: Some(Vec::new()),
            ..Self::default()
        }
    }

    /// What a [`Self::capturing`] `Deferred` was given.
    #[cfg(test)]
    pub fn captured(&self) -> String {
        String::from_utf8_lossy(self.captured.as_deref().unwrap_or_default()).into_owned()
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
        #[cfg(test)]
        if let Some(captured) = self.captured.as_mut() {
            captured.extend_from_slice(buf);
        }
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
/// Width of the reason line below each `moat demo` row.
const DEMO_REASON_WIDTH: usize = 100;

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
            &truncate(
                &format!("    {}: {}", row.shows, row.reason),
                DEMO_REASON_WIDTH,
            ),
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
            "{} UTC  {}  {}  {}  {} decisions ({} denied, {} reviewed)",
            clock(session.first_ms),
            session.session_id,
            session.host,
            session.cwd.as_deref().unwrap_or("-"),
            session.events.len(),
            session.count(Verdict::Deny),
            session.count(Verdict::Review),
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
                verdict_symbol(event.verdict),
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
         {} reviewed, {} denied",
        timestamp(summary.since_ms),
        summary.total,
        summary.sessions,
        summary.allowed,
        summary.deferred,
        summary.reviewed,
        summary.denied,
    )?;
    let centi = summary.reviews_per_active_hour_centi();
    writeln!(
        out,
        "reviews per active hour: {}.{:02}  ({} active hours)",
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
        writeln!(out, "top rules (review + deny):")?;
        for (rule, n) in &summary.top_rules {
            line(&mut out, &format!("  {n:>5}  {rule}"))?;
        }
    }
    Ok(())
}

/// The one mark a verdict has in every command's text output (`policy check`,
/// `demo`, `show`, `replay`, `watch`): `✓` allow, `→` defer, `?` review, `✕`
/// deny. Each is a single column wide, so the tables that pad by characters
/// line up in a terminal.
pub(crate) fn verdict_symbol(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "✓",
        Verdict::Defer => "→",
        Verdict::Review => "?",
        // `Deny`, and any verdict added to the core later.
        _ => "✕",
    }
}

fn kind_of(action: &Action) -> &'static str {
    match action.shown() {
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

/// `✓ allow`, `→ defer`, `? review`, `✕ deny` ([`verdict_symbol`]).
fn verdict_mark(verdict: Verdict) -> String {
    format!("{} {}", verdict_symbol(verdict), verdict.as_str())
}

pub fn describe(event: &Event) -> String {
    if event.action_unreadable {
        return format!("{} (action unreadable)", event.tool);
    }
    let tool = &event.tool;
    match event.action.as_ref().map(Action::shown) {
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

/// `text` with every control character (C0, DEL and C1) and every invisible
/// bidirectional or format character ([`hidden`]) shown as `?`.
///
/// Commands, paths, reasons and ids come from what an agent sent; written raw,
/// an escape sequence in one could set the terminal title or write the
/// clipboard (OSC 52) when a person reads it, and a right-to-left override
/// could show a rule's text in another order than it is read. One character
/// stays one, so column widths hold.
pub fn clean(text: &str) -> Cow<'_, str> {
    if text.chars().any(unsafe_to_show) {
        Cow::Owned(
            text.chars()
                .map(|c| if unsafe_to_show(c) { '?' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

/// A name read from a file or a host (an MCP server's, say), as a command
/// prints it: in backticks, through [`clean`]. Formatting one is the only way
/// a command prints such a name, so no print can leave out the cleaning.
#[derive(Debug, Clone, Copy)]
pub struct Named<'a>(pub &'a str);

impl std::fmt::Display for Named<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}`", clean(self.0))
    }
}

/// [`clean`] for each line of `text`: the line breaks stay, every other
/// character [`clean`] replaces is `?`.
pub fn clean_lines(text: &str) -> String {
    text.split('\n').map(clean).collect::<Vec<_>>().join("\n")
}

fn unsafe_to_show(c: char) -> bool {
    c.is_control() || hidden(c)
}

/// How many characters of `text` a terminal does not draw as they are read:
/// those [`clean`] shows as `?`, except line breaks and tabs. A model reads
/// each of them; a person reading the text in a terminal sees nothing there,
/// so `openmoat mcp accept` says how many a definition holds.
pub fn invisible_count(text: &str) -> usize {
    text.chars()
        .filter(|&c| unsafe_to_show(c) && !matches!(c, '\n' | '\t'))
        .count()
}

/// Characters that are not drawn, or not as what they are, but that a model
/// reads: every format character (Unicode General Category Cf), among them the
/// bidirectional marks, embeddings, overrides and isolates, the zero-width
/// characters, the invisible operators (U+2061 to U+2064), the soft hyphen
/// (U+00AD) and the tag characters (U+E0000 to U+E007F), which spell ASCII
/// text no terminal shows; the variation selectors (U+180B to U+180F, U+FE00
/// to U+FE0F, U+E0100 to U+E01EF), which can carry bytes; the blank Hangul
/// fillers and the combining grapheme joiner; and the Unicode line and
/// paragraph separators (U+2028, U+2029).
///
/// An emoji's U+FE0F and U+200D show as `?` too: the cost of a check a server's
/// text cannot get past.
fn hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
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

    #[test]
    fn bidirectional_and_invisible_characters_become_question_marks() {
        assert_eq!(
            clean("make \u{202E}yolped\u{202C} \u{2066}x\u{2069}\u{200B}\u{FEFF}\u{2028}"),
            "make ?yolped? ?x????"
        );
        assert!(matches!(clean("café ✔ 日本"), Cow::Borrowed(_)));
    }

    #[test]
    fn tag_characters_variation_selectors_and_format_characters_become_question_marks() {
        // "Ignore" spelled in tag characters, then a variation selector, a soft
        // hyphen, an invisible operator and an inhibit-swapping mark.
        let tagged =
            "read files\u{E0049}\u{E0067}\u{E006E}\u{FE0F}\u{E0100}\u{AD}\u{2062}\u{206A}.";
        assert_eq!(clean(tagged), "read files????????.");
        assert_eq!(invisible_count(tagged), 8);
        assert_eq!(invisible_count("two\nlines\tand a tab"), 0);
        assert_eq!(invisible_count("bell\x07"), 1);
    }

    #[test]
    fn clean_lines_keeps_line_breaks_only() {
        assert_eq!(
            clean_lines("a\x1b[2J\nb\u{202E}\r\n\x1b]52;c;eA==\x07"),
            "a?[2J\nb??\n?]52;c;eA==?"
        );
    }
}

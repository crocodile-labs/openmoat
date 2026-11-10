//! `openmoat doctor`'s text output: what needs the person first, each agent's
//! protection, OpenMoat's own state, and, with `--verbose`, every check and
//! each agent's known gaps. The checks are the rows `--format json` lists
//! (`json.rs`); this only places and words them for a person.

use std::io::Write as _;

use openmoat_hosts::Host;

use super::json::{Row as JsonRow, Status};
use super::{Area, Report};
use crate::protection::Protection;
use crate::report::{self, Attention, Mark, Printer, Row};

/// Where a check's row goes in the text output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Place {
    /// `Needs your attention`.
    Attention,
    /// Under the agent rows.
    Agents,
    /// The `OpenMoat` section.
    OpenMoat,
    /// Only with `--verbose`.
    Details,
}

/// One row of the text output and where it goes.
pub(super) struct Placed {
    pub place: Place,
    pub row: Row,
}

/// Where a check goes when its caller does not say: a problem or a warning
/// needs the person, except the notes on `openmoat run`, which leave the
/// hooks as they are; OpenMoat's own fine checks are shown, the rest only
/// with `--verbose` (each agent's line says what they add up to).
pub(super) fn default_place(status: Status, area: Option<Area>, name: &str) -> Place {
    match status {
        Status::Warning if name == "openmoat run" => Place::OpenMoat,
        Status::Problem | Status::Warning => Place::Attention,
        Status::Ok | Status::Note => match area {
            Some(Area::Policy | Area::Lock | Area::Audit | Area::Mcp | Area::Service) => {
                Place::OpenMoat
            }
            _ => Place::Details,
        },
    }
}

/// The text row for a check: its label, its text and the fix it ends with.
pub(super) fn default_row(status: Status, row: &JsonRow, place: Place) -> Row {
    let mark = match status {
        Status::Ok => Mark::Ok,
        Status::Problem => Mark::Broken,
        // A warning shown beside the rest of a section reads as information.
        Status::Warning if place == Place::OpenMoat => Mark::Info,
        Status::Warning => Mark::Attention,
        Status::Note => Mark::Info,
    };
    if place == Place::Details {
        return Row::new(mark, label(&row.name), row.detail.clone());
    }
    let (text, fix) = report::split_fix(&row.detail);
    let row = Row::new(mark, label(&row.name), text);
    match fix {
        Some(fix) => row.fix(fix),
        None => row,
    }
}

/// A check's left column as a heading word: `lock` is `Lock`, `mcp servers`
/// `MCP servers`; an agent's name and a command stay as they are.
pub(super) fn label(name: &str) -> String {
    if Host::EVERY.iter().any(|h| h.display_name() == name) || name.starts_with("openmoat") {
        return name.to_owned();
    }
    if let Some(rest) = name.strip_prefix("mcp ") {
        return format!("MCP {rest}");
    }
    let mut chars = name.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// The title, then every section; the footer comes after `--accept`'s
/// questions ([`footer`]).
pub(super) fn sections(report: &mut Report, agents: &[Protection], verbose: bool) {
    let mut text = Vec::new();
    // Written to a buffer first: `Report::out` keeps any error for `finish`.
    let _ = render(
        &report.human,
        agents,
        verbose,
        &mut Printer::stdout(&mut text),
    );
    let _ = report.out.write_all(&text);
}

/// The sections for `human`'s rows and `agents`' protection levels.
pub(super) fn render(
    human: &[Placed],
    agents: &[Protection],
    verbose: bool,
    out: &mut Printer<'_, Vec<u8>>,
) -> std::io::Result<()> {
    let mut attention = Attention::default();
    for placed in human.iter().filter(|p| p.place == Place::Attention) {
        attention.push(placed.row.clone());
    }
    let mut table = report::agent_table(agents, &attention, verbose);
    let rows = |place: Place| human.iter().filter(move |p| p.place == place);
    table.rows.extend(report::os_sandbox_rows(agents));
    table
        .rows
        .extend(rows(Place::Agents).map(|p| p.row.clone()));
    let sections = Sections {
        attention: &attention,
        agents: &table,
        openmoat: rows(Place::OpenMoat).map(|p| &p.row).collect(),
        details: verbose.then(|| rows(Place::Details).map(|p| &p.row).collect()),
    };
    sections.write(out)
}

/// The sections of the text output, in order.
struct Sections<'a> {
    attention: &'a Attention,
    agents: &'a report::AgentTable,
    openmoat: Vec<&'a Row>,
    /// Every other check, with `--verbose`.
    details: Option<Vec<&'a Row>>,
}

impl Sections<'_> {
    fn write(&self, out: &mut Printer<'_, Vec<u8>>) -> std::io::Result<()> {
        out.title("doctor")?;
        out.attention(self.attention)?;
        out.agents(self.agents)?;
        out.heading("OpenMoat")?;
        out.rows(self.openmoat.iter().copied())?;
        if let Some(details) = &self.details {
            out.heading("Every check")?;
            out.rows(details.iter().copied())?;
        }
        Ok(())
    }
}

/// The closing line: how many things need the person and, while something is
/// wrong, how to repair it; `All good.` when nothing needs them.
pub(super) fn footer(report: &mut Report, verbose: bool) {
    let line = footer_line(&report.human, report.problems.len(), verbose);
    let style = report::Style::detect();
    let _ = writeln!(report.out);
    let _ = writeln!(report.out, "{}", style.dim(&line));
}

/// [`footer`]'s text, for `problems` problems left and `human`'s warnings.
pub(super) fn footer_line(human: &[Placed], problems: usize, verbose: bool) -> String {
    let warnings = human
        .iter()
        .filter(|p| p.place == Place::Attention && p.row.mark == Mark::Attention)
        .count();
    let total = warnings + problems;
    let gaps = if verbose {
        String::new()
    } else {
        " · known gaps per agent: openmoat doctor --verbose".to_owned()
    };
    if total == 0 {
        format!("All good.{gaps}")
    } else if problems == 0 {
        format!(
            "{} need{} you{gaps}",
            report::count(total, "thing"),
            verb_s(total)
        )
    } else {
        format!(
            "{} need{} you · `openmoat init` re-installs and re-pins; \
             `openmoat doctor --accept` accepts edits you made yourself",
            report::count(total, "thing"),
            verb_s(total)
        )
    }
}

/// `s` for a verb after one thing: `1 thing needs`, `2 things need`.
fn verb_s(n: usize) -> &'static str {
    if n == 1 { "s" } else { "" }
}

#[cfg(test)]
mod tests;

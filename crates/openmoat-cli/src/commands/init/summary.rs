//! The end of `openmoat init`: how many agents are protected, each one's
//! protection, the steps left to the person (only those this run needs), and
//! how to undo it.

use std::io::{self, Write as _};
use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use crate::home::Home;
use crate::protection::Protection;
use crate::render::{Deferred, clean};
use crate::report::{self, Attention, Mark, Style};

/// What this run leaves to the person.
#[derive(Debug, Default)]
pub(super) struct Steps {
    /// Each agent whose own record of trusted hooks needs the person, with
    /// the step (Codex's `/hooks`).
    pub trust: Vec<(&'static str, &'static str)>,
    /// The policy update `openmoat policy upgrade` would offer.
    pub update: Option<String>,
    /// Whether an agent's files changed, so its running sessions are behind.
    pub changed: bool,
}

impl Steps {
    /// The numbered steps, in the order to take them.
    fn lines(&self, protected: usize) -> Vec<String> {
        let mut lines: Vec<String> = self
            .trust
            .iter()
            .map(|(name, step)| format!("{name}: {step}"))
            .collect();
        if let Some(update) = &self.update {
            lines.push(format!(
                "Review the new default rules ({update}): openmoat policy upgrade"
            ));
        }
        if self.changed {
            lines.push("Restart your agents (a new session reads the new settings)".to_owned());
        }
        if protected > 0 {
            lines.push("Try it: openmoat policy check \"cat ~/.ssh/id_rsa\"".to_owned());
        }
        lines
    }
}

/// The closing part of the output: the count, the table, the next steps and
/// the footer.
pub(super) fn write(
    home: &Home,
    binary: &Path,
    hosts: &[Host],
    steps: &Steps,
    backups: usize,
    verbose: bool,
    out: &mut Deferred,
) -> Result<()> {
    let agents: Vec<_> = crate::protection::report(home, binary)?
        .into_iter()
        .filter(|a| hosts.iter().any(|h| h.id() == a.host))
        .collect();
    let done = Done {
        agents: &agents,
        steps,
        backups,
        verbose,
    };
    let mut text = Vec::new();
    done.render(Style::detect(), &report::Paths::detect(), &mut text)?;
    out.write_all(&text)?;
    Ok(())
}

/// What `init` did, as the end of its output shows it.
pub(super) struct Done<'a> {
    /// The protection of each agent set up in this run.
    pub agents: &'a [Protection],
    pub steps: &'a Steps,
    /// How many backups OpenMoat holds of the agents' files.
    pub backups: usize,
    pub verbose: bool,
}

impl Done<'_> {
    pub fn render(&self, style: Style, paths: &report::Paths, out: &mut Vec<u8>) -> io::Result<()> {
        let (agents, steps, verbose) = (self.agents, self.steps, self.verbose);
        let protected = agents.iter().filter(|a| a.level.hooked()).count();
        if !agents.is_empty() {
            writeln!(out)?;
            let (mark, line) = if protected == agents.len() {
                (
                    Mark::Ok,
                    format!("{} protected", report::count(protected, "agent")),
                )
            } else {
                let all = report::count(agents.len(), "agent");
                (Mark::Attention, format!("{protected} of {all} protected"))
            };
            writeln!(out, "{} {line}", style.mark(mark))?;
            let table = report::agent_table(agents, &Attention::default(), verbose);
            write_table(&table, style, paths, out)?;
        }
        let lines = steps.lines(protected);
        if !lines.is_empty() {
            writeln!(out)?;
            writeln!(out, "{}", style.bold("Next steps"))?;
            for (n, line) in lines.iter().enumerate() {
                writeln!(out, "  {}. {}", n + 1, clean(line))?;
            }
        }
        let mut footer = Vec::new();
        if self.backups > 0 {
            footer.push("Backups saved");
        }
        if !agents.is_empty() {
            footer.push("undo everything: openmoat uninstall");
        }
        footer.push("check any time: openmoat status");
        if !verbose {
            footer.push("details: openmoat init --verbose");
        }
        writeln!(out)?;
        writeln!(out, "{}", style.dim(&footer.join(" · ")))
    }
}

/// `Agent  Protection` and a row per agent.
fn write_table(
    table: &report::AgentTable,
    style: Style,
    paths: &report::Paths,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let width = table
        .rows
        .iter()
        .map(|r| r.label.chars().count())
        .max()
        .unwrap_or(0)
        .max("Agent".len());
    writeln!(out)?;
    let header = format!("  {:<width$}  Protection", "Agent");
    writeln!(out, "{}", style.dim(&header))?;
    for row in &table.rows {
        let text = paths.shorten(&clean(&row.text));
        let text = text.trim_end();
        writeln!(
            out,
            "  {:<width$}  {} {text}",
            clean(&row.label),
            style.mark(row.mark)
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

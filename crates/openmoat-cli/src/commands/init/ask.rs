//! `openmoat init`'s question for each agent it found: one line per agent,
//! what OpenMoat would write there, then `Protect? [Y/n/d]`. An agent that
//! needs no change, and whose record stays the same, is not asked: a yes
//! would change nothing (`preview::nothing_to_do`).

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use super::preview::{self, Change};
use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::render::{Deferred, clean};
use crate::report::{Mark, Paths, Style};
use crate::sandbox::Plan;

/// One agent found, with what `init` would change there.
struct Found<'a> {
    config: &'a HostConfig,
    dir: String,
    changes: Vec<Change>,
    /// `None` when there is nothing to ask.
    what: Option<String>,
}

/// How `init` asks.
pub(super) struct Asking<'a> {
    pub plan: Option<&'a Plan>,
    /// Each file's summary before its agent's question.
    pub verbose: bool,
    /// Ask about every agent, even one with nothing to change: a yes does
    /// more than its files (`--mcp-proxy` wraps the servers of each agent
    /// accepted).
    pub every_agent: bool,
}

/// Ask about each of `found` at the terminal; the hosts to set up.
pub(super) fn ask(
    home: &Home,
    found: &[HostConfig],
    binary: &Path,
    asking: &Asking<'_>,
    out: &mut Deferred,
) -> Result<Vec<Host>> {
    let (style, paths) = (Style::detect(), Paths::detect());
    let verbose = asking.verbose;
    let mut agents = Vec::new();
    for config in found {
        let changes = preview::changes(home, config, binary, asking.plan)?;
        let what = if !asking.every_agent && preview::nothing_to_do(home, config, binary, &changes)?
        {
            None
        } else if changes.is_empty() {
            Some("no change to its files".to_owned())
        } else {
            let installed = config.state(binary) == HookState::Installed;
            Some(preview::what(&changes, installed))
        };
        agents.push(Found {
            config,
            dir: paths.path(config.dir()),
            changes,
            what,
        });
    }
    let widths = Widths {
        name: width(agents.iter().map(|a| a.config.host.display_name())),
        dir: width(agents.iter().map(|a| a.dir.as_str())),
        what: width(agents.iter().filter_map(|a| a.what.as_deref())),
    };
    writeln!(out, "{}", style.dim(INTRO))?;
    writeln!(out)?;
    let mut chosen = Vec::new();
    for agent in &agents {
        let name = agent.config.host.display_name();
        if verbose {
            preview::summary(agent.config, &agent.changes, out)?;
        }
        let line = widths.line(name, &agent.dir, agent.what.as_deref(), style);
        if agent.what.is_none() {
            writeln!(out, "{line}")?;
            chosen.push(agent.config.host);
            continue;
        }
        loop {
            write!(out, "{line}")?;
            out.flush()?;
            // End of input is a no: nothing is changed that a person did not accept.
            let answer = crate::terminal::read_answer()?;
            if answer.is_empty() {
                writeln!(out)?;
                break;
            }
            match answer.trim().to_ascii_lowercase().as_str() {
                "d" | "diff" => preview::diff(&agent.changes, out)?,
                "" | "y" | "yes" => {
                    chosen.push(agent.config.host);
                    break;
                }
                _ => break,
            }
        }
    }
    Ok(chosen)
}

/// What every question is under: the person's consent covers this.
pub(super) const INTRO: &str =
    "  Each file is backed up first · d shows the full diff · openmoat uninstall undoes it";

/// The columns of the agent lines.
pub(super) struct Widths {
    pub name: usize,
    pub dir: usize,
    pub what: usize,
}

impl Widths {
    /// An agent's line: its name, its directory and what it would get, then
    /// the question; `✔ already set up` when there is nothing to ask (`what`
    /// is `None`).
    pub fn line(&self, name: &str, dir: &str, what: Option<&str>, style: Style) -> String {
        let (name_w, dir_w, what_w) = (self.name, self.dir, self.what);
        let head = clean(&format!("  {name:<name_w$}  {dir:<dir_w$}")).into_owned();
        if let Some(what) = what {
            format!("{head}  {what:<what_w$}  Protect? [Y/n/d] ")
        } else {
            let set_up = format!("{:<what_w$}", "already set up");
            format!("{head}  {set_up}  {}", style.mark(Mark::Ok))
        }
    }
}

/// The widest of `texts`, in characters.
fn width<'a>(texts: impl Iterator<Item = &'a str>) -> usize {
    texts.map(|t| t.chars().count()).max().unwrap_or(0)
}

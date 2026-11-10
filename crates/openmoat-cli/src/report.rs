//! The shape `openmoat init`, `doctor` and `status` print in: a title, what
//! needs the person first (each with its fix), one line per agent, then
//! sections of rows. The same symbols everywhere: `✔` fine, `!` needs you, `✗`
//! broken or not protected, `·` information, `–` not installed. Colour only on
//! a terminal and never with `NO_COLOR` ([`Style`]); paths under the home
//! directory as `~/…` ([`Paths`]). Only the human text uses this: every
//! `--format json` document is built from the commands' own data.

mod agents;
mod paths;
mod style;
#[cfg(test)]
mod tests;

use std::io::{self, Write};

pub use agents::{AgentTable, agent_table, os_sandbox_rows};
pub use paths::Paths;
pub use style::Style;

use crate::render::clean;

/// How a row reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// `✔`: fine.
    Ok,
    /// `!`: needs a look from the person.
    Attention,
    /// `✗`: broken, or an agent not protected.
    Broken,
    /// `·`: information.
    Info,
    /// `–`: not installed here.
    Absent,
}

impl Mark {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Ok => "✔",
            Self::Attention => "!",
            Self::Broken => "✗",
            Self::Info => "·",
            Self::Absent => "–",
        }
    }
}

/// One line of a section: a mark, a label column, the text and, for a row
/// that needs the person, the command or step that fixes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub mark: Mark,
    pub label: String,
    pub text: String,
    pub fix: Option<String>,
}

impl Row {
    pub fn new(mark: Mark, label: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            mark,
            label: label.into(),
            text: text.into(),
            fix: None,
        }
    }

    /// The row with `fix` shown after an arrow.
    #[must_use]
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// What needs the person, gathered from every check: broken things first,
/// then the rest, each group in the order the checks found them.
#[derive(Debug, Default)]
pub struct Attention {
    rows: Vec<Row>,
}

impl Attention {
    pub fn push(&mut self, row: Row) {
        self.rows.push(row);
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The rows in the order they are shown.
    pub fn rows(&self) -> Vec<&Row> {
        let broken = self.rows.iter().filter(|r| r.mark == Mark::Broken);
        let rest = self.rows.iter().filter(|r| r.mark != Mark::Broken);
        broken.chain(rest).collect()
    }

    /// Whether a row is about `label` (an agent's name).
    pub fn names(&self, label: &str) -> bool {
        self.rows.iter().any(|r| r.label == label)
    }
}

/// Writes the title, sections and rows to `out`, cleaned of control
/// characters ([`clean`]), paths shortened and marks coloured as `style` says.
pub struct Printer<'a, W: Write> {
    out: &'a mut W,
    style: Style,
    paths: Paths,
}

impl<'a, W: Write> Printer<'a, W> {
    pub fn new(out: &'a mut W, style: Style, paths: Paths) -> Self {
        Self { out, style, paths }
    }

    /// A printer for this terminal and this user's home directory.
    pub fn stdout(out: &'a mut W) -> Self {
        Self::new(out, Style::detect(), Paths::detect())
    }

    /// The command's first line, `OpenMoat <version> · <what>`.
    pub fn title(&mut self, what: &str) -> io::Result<()> {
        let title = format!("OpenMoat {} · {what}", crate::VERSION);
        writeln!(self.out, "{}", self.style.bold(&title))
    }

    /// A blank line, then a section heading.
    pub fn heading(&mut self, heading: &str) -> io::Result<()> {
        writeln!(self.out)?;
        writeln!(self.out, "{}", self.style.bold(heading))
    }

    /// `rows`, two spaces in, their labels in one column.
    pub fn rows<'r>(&mut self, rows: impl IntoIterator<Item = &'r Row>) -> io::Result<()> {
        let rows: Vec<&Row> = rows.into_iter().collect();
        let width = rows
            .iter()
            .map(|r| r.label.chars().count())
            .max()
            .unwrap_or(0);
        for row in rows {
            let line = self.row_text(row, width);
            writeln!(self.out, "  {} {line}", self.style.mark(row.mark))?;
        }
        Ok(())
    }

    /// `Needs your attention (N)` and its rows; nothing when nothing does.
    pub fn attention(&mut self, attention: &Attention) -> io::Result<()> {
        if attention.is_empty() {
            return Ok(());
        }
        self.heading(&format!("Needs your attention ({})", attention.len()))?;
        self.rows(attention.rows())
    }

    /// The `Agents` section: one row per agent, then the ones not installed.
    pub fn agents(&mut self, table: &AgentTable) -> io::Result<()> {
        self.heading("Agents")?;
        self.rows(&table.rows)?;
        if table.rows.is_empty() && table.not_installed.is_empty() {
            writeln!(self.out, "  {}", self.style.dim("no agent found"))?;
        }
        if !table.not_installed.is_empty() {
            let line = format!("Not installed: {}", table.not_installed.join(", "));
            let mark = self.style.mark(Mark::Absent);
            writeln!(self.out, "  {mark} {}", self.style.dim(&line))?;
        }
        Ok(())
    }

    fn row_text(&self, row: &Row, width: usize) -> String {
        let label = clean(&row.label);
        let pad = width.saturating_sub(label.chars().count());
        let mut text = format!("{label}{}  {}", " ".repeat(pad), clean(&row.text));
        if let Some(fix) = &row.fix {
            text.push_str(" → ");
            text.push_str(&clean(fix));
        }
        let text = self.paths.shorten(text.trim_end());
        if width == 0 {
            text.trim_start().to_owned()
        } else {
            text
        }
    }
}

/// `detail` split at the step it ends with, as the checks write it: a detail
/// ending `; run` and a command in backticks, or `(run` and one, becomes the
/// text and the fix (`openmoat init`).
pub fn split_fix(detail: &str) -> (String, Option<String>) {
    if let Some(inner) = detail
        .strip_suffix("`)")
        .and_then(|d| d.rsplit_once(" (run `"))
    {
        return (inner.0.to_owned(), Some(inner.1.to_owned()));
    }
    match detail.split_once("; run `") {
        Some((text, rest)) => {
            let fix = rest.replacen('`', "", 1);
            (text.to_owned(), Some(fix.trim().to_owned()))
        }
        None => (detail.to_owned(), None),
    }
}

/// `n` and the noun, plural unless `n` is 1: `1 agent`, `2 agents`.
pub fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

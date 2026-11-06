//! What `openmoat policy check-diff` shows from provenance notes (ADR-056).
//!
//! The one interface check-diff has to it: [`section`] reads the notes of
//! the commits from where `--head` left `--base` to `--head` (none with a diff
//! on stdin), and [`write()`] prints the report check-diff built with that
//! section beside it: one more `provenance` key in JSON, `::warning` (or
//! `::notice`) workflow commands and lines after the text. It never changes
//! check-diff's exit code, and a commit range whose notes cannot be read is a
//! line in the section, not an error. With no notes in the range nothing is
//! printed: a missing note proves nothing, and saying so on every pull
//! request would be noise.

use std::io::{self, Write as _};

use anyhow::Result;
use openmoat_core::attribution::{Note, SessionSummary, summarise};
use serde::Serialize;

use super::NOTES_REF;
use super::git::Reader;
use super::notes::decode;
use crate::cli::{DiffFormat, ProvenanceLevel};
use crate::render;

/// The provenance part of a check-diff report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Section {
    /// `review` or `info`: how the lines are shown; never a verdict.
    pub level: &'static str,
    /// How many commits of the change have a note.
    pub noted_commits: usize,
    /// How many commits the change has.
    pub commits: usize,
    /// Notes that could not be read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<String>,
    /// What each agent session wrote.
    pub sessions: Vec<SessionSummary>,
    /// Why the notes could not be read at all, when they could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The section for the change `base`..`head` (`HEAD` by default) at `level`;
/// `None` when it is off, there is no range, or no commit has a note.
pub fn section(base: Option<&str>, head: Option<&str>, level: ProvenanceLevel) -> Option<Section> {
    let level = match level {
        ProvenanceLevel::Off => return None,
        ProvenanceLevel::Review => "review",
        ProvenanceLevel::Info => "info",
    };
    let base = base?;
    let empty = |error: Option<String>| Section {
        level,
        noted_commits: 0,
        commits: 0,
        unreadable: Vec::new(),
        sessions: Vec::new(),
        error,
    };
    let read = || -> Result<(usize, Vec<Note>, Vec<String>)> {
        let git = Reader::here()?;
        let commits = git.change(base, head.unwrap_or("HEAD"))?;
        let blobs = git.noted()?;
        let mut notes = Vec::new();
        let mut unreadable = Vec::new();
        for commit in &commits {
            let Some(blob) = blobs.get(commit) else {
                continue;
            };
            match git.note_text(blob).and_then(|t| decode(&t)) {
                Ok(note) if &note.commit == commit => notes.push(note),
                _ => unreadable.push(commit.clone()),
            }
        }
        Ok((commits.len(), notes, unreadable))
    };
    match read() {
        Ok((_, notes, unreadable)) if notes.is_empty() && unreadable.is_empty() => None,
        Ok((commits, notes, unreadable)) => Some(Section {
            noted_commits: notes.len() + unreadable.len(),
            commits,
            sessions: summarise(&notes),
            unreadable,
            ..empty(None)
        }),
        Err(error) => Some(empty(Some(format!("{error:#}")))),
    }
}

/// The JSON report with the section beside check-diff's own keys.
#[derive(Serialize)]
pub struct WithSection<'a, R> {
    /// check-diff's report, its keys unchanged.
    #[serde(flatten)]
    pub report: &'a R,
    pub provenance: &'a Section,
}

/// Print `report` as check-diff would (`plain`), with `section` added.
pub fn write<R: Serialize>(
    format: DiffFormat,
    report: &R,
    section: Option<&Section>,
    plain: impl FnOnce(DiffFormat, &R) -> Result<()>,
) -> Result<()> {
    let Some(section) = section else {
        return plain(format, report);
    };
    if format == DiffFormat::Json {
        return render::json(&WithSection {
            report,
            provenance: section,
        });
    }
    let mut out = io::stdout().lock();
    if format == DiffFormat::Github {
        for line in annotations(section) {
            writeln!(out, "{line}")?;
        }
    }
    plain(format, report)?;
    text(&mut out, section)?;
    Ok(())
}

/// One line per session: "3 files / 40 lines written by claude-code (session
/// 1a2b…, after reading web content)".
pub fn lines(section: &Section) -> Vec<String> {
    section
        .sessions
        .iter()
        .map(|s| {
            let files = match s.files {
                1 => "1 file".to_owned(),
                n => format!("{n} files"),
            };
            let lines = match s.lines {
                0 => String::new(),
                1 => " / 1 line".to_owned(),
                n => format!(" / {n} lines"),
            };
            let after = s
                .untrusted
                .as_ref()
                .map(|u| format!(", after reading {} ({})", u.kind.describe(), u.source))
                .unwrap_or_default();
            format!(
                "{files}{lines} written by {} (session {}{after})",
                s.host,
                short(&s.session)
            )
        })
        .collect()
}

pub fn text(out: &mut impl io::Write, section: &Section) -> io::Result<()> {
    let tag = format!("{:<7}", section.level);
    if let Some(error) = &section.error {
        return writeln!(
            out,
            "{tag} provenance: the notes on {NOTES_REF} could not be read: {}",
            render::clean(error)
        );
    }
    for line in lines(section) {
        writeln!(out, "{tag} provenance: {}", render::clean(&line))?;
    }
    for commit in &section.unreadable {
        writeln!(
            out,
            "{tag} provenance: the note on {} is not an OpenMoat provenance note",
            short(commit)
        )?;
    }
    writeln!(
        out,
        "        {} of {} commits have a note on {NOTES_REF}; notes are claims from the machine \
         that wrote them (`openmoat provenance --verify` there checks them), and a commit \
         without one proves nothing",
        section.noted_commits, section.commits
    )
}

/// The workflow commands: `warning` at `review`, `notice` at `info`.
pub fn annotations(section: &Section) -> Vec<String> {
    let command = if section.level == "review" {
        "warning"
    } else {
        "notice"
    };
    let title = "title=OpenMoat provenance";
    let mut out: Vec<String> = lines(section)
        .iter()
        .map(|line| format!("::{command} {title}::{}", data(line)))
        .collect();
    if let Some(error) = &section.error {
        out.push(format!(
            "::{command} {title}::{}",
            data(&format!("notes could not be read: {error}"))
        ));
    }
    out
}

/// A workflow command's message: `%`, CR and LF escaped.
fn data(text: &str) -> String {
    text.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn short(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

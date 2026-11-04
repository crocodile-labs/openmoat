//! The report of `openmoat policy check-diff`: text, JSON, or GitHub Actions
//! workflow commands (`::error file=…::…`) followed by the text.
//!
//! Paths and reasons come from the change under review, so the text passes
//! through `render::clean` (no terminal control characters) and the workflow
//! commands escape what GitHub would read as their own syntax.

use std::io::{self, Write};

use anyhow::Result;
use serde::Serialize;

use super::gate::{Finding, Level};
use crate::cli::DiffFormat;
use crate::render;

/// What one check found, with where its policy came from.
#[derive(Debug, Serialize)]
pub struct Report<'a> {
    /// `clean`, `review` or `deny`: the strictest level found.
    pub result: &'static str,
    /// How many files the change touches.
    pub files: usize,
    pub policy: &'a str,
    pub repository_policy: Option<&'a str>,
    pub findings: &'a [Finding],
}

impl<'a> Report<'a> {
    pub fn new(
        findings: &'a [Finding],
        files: usize,
        policy: &'a str,
        repository_policy: Option<&'a str>,
    ) -> Self {
        Self {
            result: worst(findings).map_or("clean", Level::as_str),
            files,
            policy,
            repository_policy,
            findings,
        }
    }
}

/// The strictest level among `findings`.
pub fn worst(findings: &[Finding]) -> Option<Level> {
    findings.iter().map(|f| f.level).max()
}

pub fn write(format: DiffFormat, report: &Report<'_>) -> Result<()> {
    let mut out = io::stdout().lock();
    match format {
        DiffFormat::Json => render::json(report)?,
        DiffFormat::Text => text(&mut out, report)?,
        DiffFormat::Github => {
            for finding in report.findings {
                writeln!(out, "{}", annotation(finding))?;
            }
            text(&mut out, report)?;
        }
    }
    Ok(())
}

fn where_of(finding: &Finding) -> String {
    let path = if finding.path.is_empty() {
        "(the diff)"
    } else {
        &finding.path
    };
    match finding.line {
        Some(line) => format!("{path}:{line}"),
        None => path.to_owned(),
    }
}

pub fn text(out: &mut impl Write, report: &Report<'_>) -> io::Result<()> {
    for finding in report.findings {
        writeln!(
            out,
            "{:<7} {} [{}]",
            finding.level.as_str(),
            render::clean(&where_of(finding)),
            finding.rules.join(", ")
        )?;
        for reason in &finding.reasons {
            writeln!(out, "        {}", render::clean(reason))?;
        }
    }
    let count = |level| report.findings.iter().filter(|f| f.level == level).count();
    let checked = match report.repository_policy {
        Some(repo) => format!("{} and {}", report.policy, render::clean(repo)),
        None => report.policy.to_owned(),
    };
    match report.result {
        "clean" => writeln!(
            out,
            "clean: {} changed files, nothing {checked} protects",
            report.files
        ),
        _ => writeln!(
            out,
            "{}: {} deny, {} review in {} changed files (checked against {checked})",
            report.result,
            count(Level::Deny),
            count(Level::Review),
            report.files
        ),
    }
}

/// One workflow command: `error` for deny, `warning` for review.
pub fn annotation(finding: &Finding) -> String {
    let command = match finding.level {
        Level::Deny => "error",
        Level::Review => "warning",
    };
    let mut properties = Vec::new();
    if !finding.path.is_empty() {
        properties.push(format!("file={}", property(&finding.path)));
    }
    if let Some(line) = finding.line {
        properties.push(format!("line={line}"));
    }
    let title = format!(
        "OpenMoat {}: {}",
        finding.level.as_str(),
        finding.rules.join(", ")
    );
    properties.push(format!("title={}", property(&title)));
    format!(
        "::{command} {}::{}",
        properties.join(","),
        data(&finding.reasons.join("; "))
    )
}

/// A workflow command's message: `%`, CR and LF escaped.
fn data(text: &str) -> String {
    text.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// A workflow command's property value: also `:` and `,`.
fn property(text: &str) -> String {
    data(text).replace(':', "%3A").replace(',', "%2C")
}

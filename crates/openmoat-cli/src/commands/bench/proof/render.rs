//! The proof report as text for a terminal and as Markdown for a pull request
//! or an audit file. JSON is the [`super::Report`] itself.

use std::fmt::Write as _;
use std::io::{self, Write as _};

use anyhow::Result;

use super::Report;

/// What a person reads first: hook-level detection and OS-level enforcement
/// are separate rows, and a row that did not run is not a pass.
const LEGEND: &str = "Each row is one layer of one promise. policy decision: what OpenMoat's \
                      engine decides; host model (golden payloads): OpenMoat's own model of \
                      each host's payload and of its reading of the reply, no host program \
                      run; real host: the host program itself, not run by this report; OS \
                      sandbox: the attack run under `openmoat run`; network boundary: the \
                      proxy's decision. NOT TESTED HERE is not a pass.";

fn header(report: &Report) -> Vec<(&'static str, String)> {
    let hosts = report
        .hosts
        .iter()
        .map(|h| format!("{} ({}, not run)", h.id, h.evidence))
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        ("OpenMoat", report.openmoat.to_owned()),
        ("system", report.os.clone()),
        (
            "OS sandbox",
            report.os_sandbox.map_or_else(
                || "none here (`openmoat run` refuses on this system)".to_owned(),
                |b| format!("{b}, under `openmoat run`"),
            ),
        ),
        ("hosts", hosts),
        ("generated", report.generated_at.clone()),
    ]
}

fn summary(report: &Report) -> String {
    let s = &report.summary;
    format!(
        "{} pass, {} fail, {} not tested here",
        s.pass, s.fail, s.not_tested_here
    )
}

pub fn text(report: &Report) -> Result<()> {
    let mut out = String::from("MoatBench proof report\n");
    for (name, value) in header(report) {
        let _ = writeln!(out, "{name}: {value}");
    }
    let mut last = "";
    for row in &report.rows {
        if row.promise != last {
            let _ = writeln!(out, "\n{} [{}]", row.question, row.promise);
            last = row.promise;
        }
        let _ = writeln!(
            out,
            "  {:<28} {:<16} {}",
            row.layer.label(),
            row.status.word(),
            row.check
        );
        if let Some(why) = row.status.reason() {
            let _ = writeln!(out, "  {:<28} {:<16} why: {why}", "", "");
        }
        if !row.reproduce.is_empty() {
            let _ = writeln!(
                out,
                "  {:<28} {:<16} reproduce: {}",
                "",
                "",
                row.reproduce.join(", ")
            );
        }
    }
    let _ = writeln!(out, "\n{}\n{LEGEND}", summary(report));
    io::stdout().lock().write_all(out.as_bytes())?;
    Ok(())
}

pub fn markdown(report: &Report) -> Result<()> {
    let mut out = String::from("# MoatBench proof report\n\n");
    for (name, value) in header(report) {
        let _ = writeln!(out, "- **{name}**: {}", cell(&value));
    }
    let _ = write!(
        out,
        "\nSummary: {}.\n\n{LEGEND}\n\n\
         | Promise | Layer | Check | Status | Why | Reproduce |\n\
         |---|---|---|---|---|---|\n",
        summary(report)
    );
    for row in &report.rows {
        let ids = row
            .reproduce
            .iter()
            .map(|id| format!("`{id}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "| {} | {} | {} | **{}** | {} | {ids} |",
            cell(row.question),
            row.layer.label(),
            cell(&row.check),
            row.status.word(),
            cell(row.status.reason().unwrap_or("")),
        );
    }
    out.push_str(
        "\nReproduce a row with `openmoat bench --report` (add `--host <id>` for one host); \
         scenario ids are in `moatbench/<category>.yaml`, probe ids in docs/MOATBENCH.md.\n",
    );
    io::stdout().lock().write_all(out.as_bytes())?;
    Ok(())
}

/// `text` safe inside a Markdown table cell.
pub fn cell(text: &str) -> String {
    crate::render::clean(&text.replace(['\n', '\r', '\t'], " ")).replace('|', "\\|")
}

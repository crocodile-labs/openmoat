use openmoat_hosts::Host;

use super::super::rows::Report;
use super::super::{Area, json::Status};
use super::*;
use crate::protection::Level;
use crate::render::Deferred;
use crate::report::{Paths, Style};

/// Each agent's protection as a machine with five agents set up would have it.
fn agents() -> Vec<Protection> {
    Host::ALL
        .into_iter()
        .map(|host| {
            let (level, reason) = match host.id() {
                "claude-code" | "codex" => (Level::HookAndOsSandbox, None),
                "openclaw" | "copilot-cli" | "gemini-cli" => (
                    Level::HookOnly,
                    Some("no OS sandbox from OpenMoat; `openmoat run` puts it in one".to_owned()),
                ),
                _ => (Level::NotFound, None),
            };
            Protection {
                host: host.id(),
                name: host.display_name(),
                level,
                reason,
                gaps: "the agent's own web search is not checked",
                limit: None,
                required: None,
                os_sandbox: None,
            }
        })
        .collect()
}

/// The rows `doctor` makes on such a machine: two things that need the
/// person, the rest fine.
fn report() -> Report {
    let mut report = Report::new(Deferred::quiet());
    report.line(
        Area::State,
        true,
        "state directory  /Users/you/.moat".to_owned(),
    );
    report.line_as(
        Area::Policy,
        true,
        "policy           lints (16 deny, 20 allow, 12 review)".to_owned(),
        Place::OpenMoat,
        Row::new(Mark::Ok, "Policy", "16 deny · 20 allow · 12 review rules"),
    );
    report.line(
        Area::Lock,
        true,
        "lock             12 files pinned, all intact".to_owned(),
    );
    report.line(
        Area::Hook,
        true,
        "Claude Code      hook installed  /Users/you/.claude/settings.json".to_owned(),
    );
    report.warn_as(
        "Codex            hook installed but not trusted",
        Row::new(Mark::Attention, "Codex", "hook installed but not trusted")
            .fix("open Codex and trust OpenMoat's hook in /hooks"),
    );
    report
        .warn("OpenClaw         2026.5.2 has 5 security advisories; upgrade to 2026.8.1 or later");
    report.note("Cursor           host not found");
    report.warn("openmoat run     needs macOS 13 or later (this Mac: 12.7.6); the agent hooks still apply the policy");
    report.line(
        Area::Audit,
        true,
        "audit log        37485 events, hash chain intact".to_owned(),
    );
    report
}

fn rendered(report: &Report, verbose: bool) -> String {
    let mut text = Vec::new();
    let mut out = Printer::new(
        &mut text,
        Style::new(false, None),
        Paths::under(Some(std::path::Path::new("/Users/you"))),
    );
    render(&report.human, &agents(), verbose, &mut out).unwrap();
    let footer = footer_line(&report.human, report.problems.len(), verbose);
    format!("{}\n{footer}\n", String::from_utf8(text).unwrap())
}

/// `text` with each run of spaces as one, so a check does not depend on
/// the column widths.
fn squash(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if !(c == ' ' && out.ends_with(' ')) {
            out.push(c);
        }
    }
    out
}

#[test]
fn what_needs_the_person_comes_first_with_its_fix() {
    let printed = rendered(&report(), false);
    println!("{printed}");
    let shown = squash(&printed);
    let attention = shown.find("Needs your attention (2)").expect(&shown);
    let agents = shown.find("\nAgents\n").expect(&shown);
    assert!(attention < agents, "{shown}");
    assert!(
        shown.contains("! Codex hook installed but not trusted → open Codex"),
        "{shown}"
    );
    // A fine agent with something that needs the person is marked too.
    assert!(shown.contains("! Codex hook + OS sandbox\n"), "{shown}");
    assert!(
        shown.contains("✔ Claude Code hook + OS sandbox\n"),
        "{shown}"
    );
    assert!(shown.contains("✔ Gemini CLI hook only\n"), "{shown}");
    assert!(shown.contains("– Not installed: "), "{shown}");
    assert!(shown.contains("✔ Policy 16 deny"), "{shown}");
    assert!(shown.contains("· openmoat run needs macOS 13"), "{shown}");
    assert!(
        shown.ends_with("2 things need you · known gaps per agent: openmoat doctor --verbose\n")
    );
    // Paths and every check only with --verbose.
    assert!(!shown.contains("settings.json"), "{shown}");
    assert!(!shown.contains("host not found"), "{shown}");
}

#[test]
fn verbose_lists_every_check_with_its_path_shortened() {
    let printed = rendered(&report(), true);
    println!("{printed}");
    let shown = squash(&printed);
    assert!(shown.contains("Every check"), "{shown}");
    assert!(
        shown.contains("✔ Claude Code hook installed ~/.claude/settings.json"),
        "{shown}"
    );
    assert!(shown.contains("host not found"), "{shown}");
    assert!(
        shown.contains("Gemini CLI hook only (no OS sandbox"),
        "{shown}"
    );
    assert!(shown.ends_with("2 things need you\n"), "{shown}");
}

#[test]
fn nothing_to_do_is_all_good() {
    let mut report = Report::new(Deferred::quiet());
    report.line(
        Area::Lock,
        true,
        "lock             3 files pinned, all intact".to_owned(),
    );
    let shown = rendered(&report, false);
    assert!(!shown.contains("Needs your attention"), "{shown}");
    assert!(shown.contains("\nAll good."), "{shown}");
}

#[test]
fn a_problem_goes_first_and_names_the_repair() {
    let mut report = report();
    report.line(
        Area::Hook,
        false,
        "Gemini CLI       hook missing; run `openmoat init`".to_owned(),
    );
    let shown = squash(&rendered(&report, false));
    let problem = shown
        .find("✗ Gemini CLI hook missing → openmoat init")
        .expect(&shown);
    assert!(
        problem < shown.find("! Codex").unwrap_or(usize::MAX),
        "{shown}"
    );
    assert!(
        shown.contains("3 things need you · `openmoat init` re-installs"),
        "{shown}"
    );
}

#[test]
fn rows_keep_their_json_text() {
    let report = report();
    let codex = report.rows.iter().find(|r| r.name == "Codex").unwrap();
    assert_eq!(codex.detail, "hook installed but not trusted");
    assert_eq!(
        default_place(Status::Ok, Some(Area::Hook), "Claude Code"),
        Place::Details
    );
    assert_eq!(
        default_place(Status::Warning, None, "openmoat run"),
        Place::OpenMoat
    );
    assert_eq!(label("mcp servers"), "MCP servers");
    assert_eq!(label("pi"), "pi");
    assert_eq!(label("audit log"), "Audit log");
}

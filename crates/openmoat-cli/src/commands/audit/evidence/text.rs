//! The evidence as Markdown, for a person to read or attach. `--format json`
//! holds the same data, every sample in full.

use std::fmt::Write as _;
use std::io::{self, Write as _};

use anyhow::Result;

use super::Evidence;
use super::build::{Counts, RuleStatus, Sample, VERDICTS};
use crate::compliance::Framework;
use crate::render;

/// Width of a sample's action in the text report.
const ACTION_WIDTH: usize = 100;
/// Unmapped rules listed in the text report; JSON lists them all.
const UNMAPPED_SHOWN: usize = 15;

pub(super) fn write(evidence: &Evidence) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(markdown(evidence)?.as_bytes())?;
    Ok(())
}

pub(super) fn markdown(e: &Evidence) -> Result<String> {
    let mut md = String::new();
    writeln!(md, "# OpenMoat evidence report\n")?;
    writeln!(md, "{}\n", super::STATEMENT)?;
    let host = e
        .window
        .host
        .map(|h| format!(", host `{h}`"))
        .unwrap_or_default();
    writeln!(
        md,
        "- Window: {} to {} (UTC, end not included){host}",
        e.window.since, e.window.until
    )?;
    writeln!(md, "- Generated: {}", e.generated_at)?;
    writeln!(md, "- Decisions: {}\n", counts_line(&e.totals))?;
    log(&mut md, e)?;
    state(&mut md, e)?;
    controls(&mut md, e)?;
    groups(&mut md, e)?;
    unmapped(&mut md, e)?;
    writeln!(
        md,
        "## Limits\n\n\
         - The policy, lock and protections above are their state when this report was made; \
         the audit log does not record which policy decided each call.\n\
         - Only tool calls that reached OpenMoat are recorded: an agent that is not set up, a \
         hook that failed open, or a tool outside the hook is not in this log.\n\
         - A rule that fired is evidence that the rule operated on that call; no count here \
         says a control is designed or operating effectively.\n\
         - This machine's log only. `openmoat audit report` combines exports from several \
         machines."
    )?;
    Ok(md)
}

/// `12 (allow 9 · defer 1 · … )`: verdicts by their own names.
fn counts_line(c: &Counts) -> String {
    let by: Vec<String> = VERDICTS
        .iter()
        .map(|v| format!("{} {}", v.as_str(), c.of(*v)))
        .collect();
    format!("{} ({})", c.decisions, by.join(" · "))
}

/// `| a | b | allow | defer | … |` and its rule.
fn header(first: &[&str]) -> String {
    let names: Vec<&str> = first
        .iter()
        .copied()
        .chain(VERDICTS.iter().map(|v| v.as_str()))
        .collect();
    format!("| {} |\n|{}", names.join(" | "), "---|".repeat(names.len()))
}

/// ` 9 | 1 | … |`: one cell per verdict, after the cells already written.
fn verdict_cells(c: &Counts) -> String {
    VERDICTS.iter().fold(String::new(), |mut cells, v| {
        let _ = write!(cells, " {} |", c.of(*v));
        cells
    })
}

fn log(md: &mut String, e: &Evidence) -> Result<()> {
    writeln!(md, "## Audit log\n")?;
    let chain = &e.log.chain;
    match &chain.broken {
        Some(broken) => writeln!(
            md,
            "- Hash chain: **broken** at event {}: {}. Events from there on cannot be relied on.",
            broken.id,
            broken.kind.describe()
        )?,
        None => writeln!(
            md,
            "- Hash chain: intact over {} events{}",
            chain.events,
            chain
                .head
                .as_ref()
                .map(|h| format!(", head `{h}`"))
                .unwrap_or_default()
        )?,
    }
    if chain.unchained > 0 {
        writeln!(
            md,
            "- {} events were written before the chain existed and are not covered by it",
            chain.unchained
        )?;
    }
    match (&e.log.first_id, &e.log.last_id, &e.log.last_hash) {
        (Some(first), Some(last), Some(hash)) => writeln!(
            md,
            "- This window: events {first} to {last}; the newest has hash `{hash}`. \
             `openmoat audit export --since {} > window.jsonl` and \
             `openmoat audit verify window.jsonl --anchor {hash}` check it without the database.\n",
            e.window.since
        )?,
        _ => writeln!(md, "- This window holds no events.\n")?,
    }
    Ok(())
}

fn state(md: &mut String, e: &Evidence) -> Result<()> {
    writeln!(md, "## Policy and protections when this report was made\n")?;
    let p = &e.policy;
    let sha = p
        .sha256
        .as_ref()
        .map(|s| format!(" sha256 `{s}`"))
        .unwrap_or_default();
    let origin = if p.same_as_shipped_default {
        "the default policy this build ships"
    } else {
        "changed from the default policy this build ships"
    };
    writeln!(md, "- Policy: `{}`{sha}, {origin}", cell(&p.path))?;
    if let Some([deny, allow, review]) = p.rules {
        writeln!(
            md,
            "- Rule groups in force: {deny} deny, {allow} allow, {review} review"
        )?;
    }
    if let Some(error) = &p.error {
        writeln!(md, "- Policy error: {}", cell(error))?;
    }
    let l = &e.lock;
    if !l.present {
        writeln!(md, "- Lock: missing; nothing pins the policy or the hooks")?;
    } else if let Some(error) = &l.error {
        writeln!(md, "- Lock: cannot be read: {}", cell(error))?;
    } else {
        let intact = if l.drift.is_empty() {
            "intact".to_owned()
        } else {
            format!("**drift**: {}", cell(&l.drift.join("; ")))
        };
        writeln!(
            md,
            "- Lock: {} files pinned, {intact}; last pinned {}",
            l.files_pinned,
            l.pinned_at.as_deref().unwrap_or("-")
        )?;
        if l.pinned_since_window_start {
            writeln!(
                md,
                "- The lock was re-pinned after the window started: the policy in force during the \
                 window may differ from the one above"
            )?;
        }
    }
    writeln!(
        md,
        "\n| Agent | Protection | Why not higher |\n|---|---|---|"
    )?;
    for agent in &e.protections {
        writeln!(
            md,
            "| {} | {} | {} |",
            agent.name,
            agent.level.label(),
            cell(agent.reason.as_deref().unwrap_or(""))
        )?;
    }
    writeln!(md)?;
    Ok(())
}

fn controls(md: &mut String, e: &Evidence) -> Result<()> {
    writeln!(md, "## Controls\n")?;
    for framework in Framework::ALL {
        writeln!(md, "### {}\n", framework.name())?;
        writeln!(md, "{}", header(&["Control", "Rule groups", "Decisions"]))?;
        for c in e.controls.iter().filter(|c| c.framework == framework) {
            writeln!(
                md,
                "| {} {} | {} | {} |{}",
                c.id,
                c.title,
                c.groups.join(", "),
                c.counts.decisions,
                verdict_cells(&c.counts)
            )?;
        }
        writeln!(md)?;
    }
    Ok(())
}

fn groups(md: &mut String, e: &Evidence) -> Result<()> {
    writeln!(md, "## Rule groups\n")?;
    for g in &e.groups {
        writeln!(md, "### {} (`{}`)\n", g.title, g.id)?;
        writeln!(
            md,
            "The rules {}. Controls: {}.\n",
            g.does,
            g.controls.join(", ")
        )?;
        writeln!(md, "Decisions: {}\n", counts_line(&g.counts))?;
        if !g.rules.is_empty() {
            writeln!(md, "{}", header(&["Rule", "In the policy"]))?;
            for r in &g.rules {
                let status = match r.status {
                    RuleStatus::InPolicy => "yes",
                    RuleStatus::NotInPolicy => "**no**: cannot fire",
                    RuleStatus::BuiltIn => "built in",
                    RuleStatus::Unknown => "unknown",
                };
                writeln!(
                    md,
                    "| `{}` | {status} |{}",
                    r.rule,
                    verdict_cells(&r.counts)
                )?;
            }
            writeln!(md)?;
        }
        if !g.samples.is_empty() {
            writeln!(
                md,
                "Samples (newest first, the strictest verdicts before the rest; stored redacted):\n"
            )?;
            for s in &g.samples {
                writeln!(md, "{}", sample(s))?;
            }
            writeln!(md)?;
        }
    }
    Ok(())
}

fn sample(s: &Sample) -> String {
    format!(
        "- event {} · {} · {} · {} [{}] {}",
        s.id,
        s.time,
        cell(&s.host),
        s.verdict.as_str(),
        cell(&s.rules.join(", ")),
        code(&render::truncate(&s.action, ACTION_WIDTH))
    )
}

fn unmapped(md: &mut String, e: &Evidence) -> Result<()> {
    if e.unmapped_rules.is_empty() {
        return Ok(());
    }
    writeln!(
        md,
        "## Rules that map to no control\n\n\
         Allow rules, the catch-all, your own rules and audit-only rows. Listed so every decision \
         in the window is accounted for.\n\n{}",
        header(&["Rule", "Decisions"])
    )?;
    for r in e.unmapped_rules.iter().take(UNMAPPED_SHOWN) {
        writeln!(
            md,
            "| {} | {} |{}",
            code(&r.rule),
            r.counts.decisions,
            verdict_cells(&r.counts)
        )?;
    }
    if e.unmapped_rules.len() > UNMAPPED_SHOWN {
        writeln!(
            md,
            "\n{} more in `--format json`.",
            e.unmapped_rules.len() - UNMAPPED_SHOWN
        )?;
    }
    writeln!(md)?;
    Ok(())
}

/// Recorded text in a table cell or list item: control and invisible
/// characters shown as `?` ([`render::clean`]), so a newline cannot start a
/// row and an escape cannot reach the terminal, and `|` escaped.
fn cell(text: &str) -> String {
    render::clean(text).replace('|', "\\|")
}

/// [`cell`] as a code span, its fence longer than any backtick run inside.
fn code(text: &str) -> String {
    let text = cell(text);
    if text.trim().is_empty() {
        return "(empty)".to_owned();
    }
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{text}{pad}{fence}")
}

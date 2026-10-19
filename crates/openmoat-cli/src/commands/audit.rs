//! `moat audit`: take the audit log off the machine in a form that can be checked.

use std::io::{self, Write as _};

use anyhow::{Context as _, Result};
use openmoat_audit::{AnchorCheck, ExportFilter, ExportReport};
use openmoat_hosts::Host;

use crate::cli::{ExportArgs, Format, VerifyArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::time;

mod anchor;

pub use anchor::run as anchor;

pub fn export(args: &ExportArgs) -> Result<Code> {
    let since_ms = time::parse_since(&args.since, time::now_ms())?;
    let store = Home::locate()?.open_audit()?;
    let events = store.export(&ExportFilter {
        since_ms,
        host: args.host.map(Host::id),
        session_id: args.session.as_deref(),
    })?;
    render::json_lines(&events)?;
    Ok(Code::Ok)
}

/// Exit 0 when every line verifies and the anchor, if given, is among them, else 64.
/// `--require-anchor` also fails a verify without an anchor. With `--against`,
/// the database is checked against the recorded anchors instead.
pub fn verify(args: &VerifyArgs) -> Result<Code> {
    let file = match (&args.against, &args.file) {
        (Some(against), _) => return anchor::verify_against(against, args.format),
        (None, Some(file)) => file,
        (None, None) => anyhow::bail!("give the export file, or --against <git repo or file>"),
    };
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let anchor = args.anchor.as_deref().map(str::trim);
    let report = openmoat_audit::verify_export(&text, anchor);
    match args.format {
        Format::Json => render::json(&report)?,
        Format::Text => verify_text(&report, args.require_anchor)?,
    }
    let anchored = match report.anchor {
        AnchorCheck::Found => true,
        AnchorCheck::NotAnchored => !args.require_anchor,
        AnchorCheck::Missing => false,
    };
    Ok(if report.broken.is_none() && anchored {
        Code::Ok
    } else {
        Code::Usage
    })
}

fn verify_text(report: &ExportReport, require_anchor: bool) -> Result<()> {
    let mut out = io::stdout().lock();
    if let Some(broken) = &report.broken {
        let event = broken
            .id
            .map(|id| format!(" (event {id})"))
            .unwrap_or_default();
        let why = match broken.id {
            Some(_) => broken.kind.describe(),
            None => "not a moat-audit-export-v1 event line",
        };
        writeln!(out, "⛔ line {}{event}: {why}", broken.line)?;
        writeln!(out, "   {} lines before it verified", report.events)?;
        return Ok(());
    }
    let (Some(first), Some(last), Some(head)) = (report.first_id, report.last_id, &report.head)
    else {
        writeln!(out, "no events")?;
        return Ok(());
    };
    let start = if report.from_genesis {
        "from the start of the log".to_owned()
    } else {
        format!("from event {first}, not the start of the log")
    };
    let not_anchored = if report.anchor == AnchorCheck::NotAnchored {
        ", not anchored"
    } else {
        ""
    };
    writeln!(
        out,
        "✔ {} events (ids {first}–{last}), hash chain intact {start}{not_anchored}",
        report.events
    )?;
    if report.gaps > 0 {
        writeln!(
            out,
            "   {} gaps in ids: a filtered export, or events deleted from the log",
            report.gaps
        )?;
    }
    writeln!(out, "head {head}")?;
    match report.anchor {
        AnchorCheck::Found => writeln!(out, "✔ anchor found")?,
        AnchorCheck::Missing => writeln!(
            out,
            "⛔ the anchor is not in this export: events up to it were rewritten or dropped, or the export covers another log or window"
        )?,
        AnchorCheck::NotAnchored if require_anchor => writeln!(
            out,
            "⛔ not anchored and --require-anchor was given: pass the head recorded earlier as --anchor"
        )?,
        AnchorCheck::NotAnchored => writeln!(
            out,
            "   not anchored: this file alone cannot show that its newest events were dropped; record the head elsewhere and pass it as --anchor later"
        )?,
    }
    Ok(())
}

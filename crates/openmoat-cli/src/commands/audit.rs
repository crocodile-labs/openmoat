//! `moat audit`: take the audit log off the machine in a form that can be checked.

use std::io::{self, Write as _};

use anyhow::{Context as _, Result};
use openmoat_audit::{AnchorCheck, CheckpointCheck, ExportFilter, ExportReport};
use openmoat_hosts::Host;

use crate::cli::{ExportArgs, Format, VerifyArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::time;

mod anchor;
mod checkpoint;
pub mod deliver;
mod evidence;
mod stats;

pub use anchor::run as anchor;
pub use checkpoint::run as checkpoint;
pub use evidence::run as evidence;
pub use stats::run as stats;

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
/// the database is checked against the recorded anchors instead. With
/// `--checkpoint`, the export (or, without one, the database) must also hold
/// what the signed checkpoint states (ADR-110).
pub fn verify(args: &VerifyArgs) -> Result<Code> {
    let signed = match (&args.checkpoint, &args.pubkey) {
        (Some(file), Some(key)) => Some((file.as_path(), key.as_str())),
        _ => None,
    };
    let file = match (&args.against, &args.file, signed) {
        (Some(against), _, _) => return anchor::verify_against(against, args.format),
        (None, Some(file), _) => file,
        (None, None, Some((cp, key))) => return checkpoint::verify_local(cp, key, args.format),
        (None, None, None) => {
            anyhow::bail!("give the export file, --checkpoint, or --against <git repo or file>")
        }
    };
    // The signature is checked before anything is read of the export.
    let checkpoint = signed
        .map(|(cp, key)| checkpoint::open(cp, key))
        .transpose()?;
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let anchor = args.anchor.as_deref().map(str::trim);
    // This machine's audit key, when there is one it can use, checks the MACs
    // of the lines it made (ADR-101); elsewhere the hash chain is checked alone.
    let key = Home::locate()
        .ok()
        .and_then(|home| crate::audit_key::read(&home).ok().flatten());
    let report = openmoat_audit::verify_export_keyed(&text, anchor, key.as_ref());
    let checked = checkpoint
        .as_ref()
        .map(|cp| openmoat_audit::check_export(&text, cp));
    match args.format {
        Format::Json => render::json(&Verified {
            report: &report,
            checkpoint: checked,
        })?,
        Format::Text => {
            verify_text(&report, args.require_anchor)?;
            if let Some(check) = checked {
                checkpoint::line(&mut io::stdout().lock(), check)?;
            }
        }
    }
    let anchored = match report.anchor {
        AnchorCheck::Found => true,
        AnchorCheck::NotAnchored => !args.require_anchor,
        AnchorCheck::Missing => false,
    };
    let signed_holds = checked.is_none_or(CheckpointCheck::holds);
    Ok(if report.broken.is_none() && anchored && signed_holds {
        Code::Ok
    } else {
        Code::Usage
    })
}

/// The export's report, and the checkpoint's check beside it when one was
/// given; without one the JSON is the report alone, as before.
#[derive(serde::Serialize)]
struct Verified<'a> {
    #[serde(flatten)]
    report: &'a ExportReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint: Option<CheckpointCheck>,
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
            None => "not a moat-audit-export-v1 or -v2 event line",
        };
        writeln!(out, "✗ line {}{event}: {why}", broken.line)?;
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
    if report.keyed > 0 {
        writeln!(
            out,
            "✔ {} events carry this machine's audit-key MAC, and each matches",
            report.keyed
        )?;
    } else if report.key_given {
        writeln!(
            out,
            "   0 lines verified with this machine's audit key: this export is not shown to be \
             this machine's log as written"
        )?;
    } else {
        writeln!(
            out,
            "   no audit key here: no MAC was checked, only the hash chain"
        )?;
    }
    if report.keyed_unchecked > 0 {
        writeln!(
            out,
            "   {} events carry an audit-key MAC that was not checked: no key here made it. \
             Their hash chain shows no event was edited on its own, not that the file was not \
             rewritten as a whole; verify on the machine that wrote them",
            report.keyed_unchecked
        )?;
    }
    writeln!(out, "head {head}")?;
    match report.anchor {
        AnchorCheck::Found => writeln!(out, "✔ anchor found")?,
        AnchorCheck::Missing => writeln!(
            out,
            "✗ the anchor is not in this export: events up to it were rewritten or dropped, or the export covers another log or window"
        )?,
        AnchorCheck::NotAnchored if require_anchor => writeln!(
            out,
            "✗ not anchored and --require-anchor was given: pass the head recorded earlier as --anchor"
        )?,
        AnchorCheck::NotAnchored => writeln!(
            out,
            "   not anchored: this file alone cannot show that its newest events were dropped; record the head elsewhere and pass it as --anchor later"
        )?,
    }
    Ok(())
}

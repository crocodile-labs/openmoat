//! `openmoat policy diff OLD NEW [--widen]` (ADR-111): what changed between
//! two policy files and, with `--widen`, whether the new one widens.
//!
//! Exit codes follow `policy check` (ADR-004): 0 nothing widens (or, without
//! `--widen`, the comparison ran), 2 something widens, 3 a setting changed in
//! a way the check does not rank, 64 a file could not be read.

use std::fs;
use std::io::{self, Write as _};

use anyhow::{Context as _, Result};
use openmoat_core::widen::{self, Effect, Report};

use crate::cli::{DiffArgs, Format};
use crate::context;
use crate::exit::Code;
use crate::render;

pub fn run(args: &DiffArgs) -> Result<Code> {
    let old = context::load_policy(&args.old)?;
    let new = context::load_policy(&args.new)?;
    let report = if args.widen {
        let mut extra = Vec::new();
        for file in &args.fixtures {
            let text =
                fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
            extra.extend(widen::fixtures(&text).with_context(|| {
                format!("{} is not a conformance fixture file", file.display())
            })?);
        }
        crate::widen::compare(&old, &new, &extra)?
    } else {
        // Rules and settings only: no case is decided.
        let mut report = widen::compare(&old, &new, &[], &[])?;
        report.sampled.clear();
        report
    };
    match args.format {
        Format::Json => render::json(&report)?,
        Format::Text => text(&report, args)?,
    }
    Ok(code(&report, args.widen))
}

fn text(report: &Report, args: &DiffArgs) -> Result<()> {
    let mut out = io::stdout().lock();
    if args.widen {
        crate::widen::write(&mut out, report, false)?;
        if !report.widens() && !report.unchecked() {
            writeln!(out, "✔ nothing widens")?;
        }
        return Ok(());
    }
    for change in &report.settings {
        let effect = match change.effect {
            Effect::Widens => "widens",
            Effect::Narrows => "narrows",
            Effect::Unchecked => "changed",
        };
        render::line(
            &mut out,
            &format!("  {effect}: {}: {}", change.setting, change.what),
        )?;
    }
    for rule in &report.rules {
        render::line(
            &mut out,
            &format!("  rule {} ({}): {}", rule.id, rule.list, rule.change),
        )?;
    }
    if report.settings.is_empty() && report.rules.is_empty() {
        writeln!(out, "no rule or setting differs")?;
    }
    writeln!(
        out,
        "`--widen` decides both policies and reports what moves toward allow"
    )?;
    Ok(())
}

/// 2 for a widening, 3 for a change not ranked, else 0; always 0 without `--widen`.
pub(super) fn code(report: &Report, widen: bool) -> Code {
    if !widen {
        Code::Ok
    } else if report.widens() {
        Code::Deny
    } else if report.unchecked() {
        Code::Review
    } else {
        Code::Ok
    }
}

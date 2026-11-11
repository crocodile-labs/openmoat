//! `openmoat snapshot [--list | --prune]` (ADR-085).
//!
//! Every form refuses when an agent started it: the store is the person's
//! record of the project, and an agent that could add snapshots could push
//! the person's out of the retention, one that could list them could read
//! the names of files it deleted.

use std::io::Write as _;

use anyhow::{Context as _, Result, bail};

use crate::cli::{Format, SnapshotArgs};
use crate::context;
use crate::exit::Code;
use crate::home::Home;
use crate::render::{self, Deferred, clean};
use crate::snapshot::{self, Limits, Reason, Retention, Store};

pub fn run(args: &SnapshotArgs) -> Result<Code> {
    crate::terminal::refuse_agent("openmoat snapshot")?;
    let home = Home::locate()?;
    home.require_exists()?;
    let ctx = context::eval_context(&home, None, None)?;
    let project = ctx.project.clone().context(
        "snapshots are of a project: run this in the project, not in your home directory, \
         one of its ancestors or a filesystem root",
    )?;
    let project = std::path::Path::new(&project);
    if args.list {
        let Some(store) = Store::existing(&home, project)? else {
            if args.format == Format::Json {
                render::json(&Vec::<snapshot::Listed>::new())?;
            } else {
                println!(
                    "no snapshots of {} yet",
                    clean(&project.display().to_string())
                );
            }
            return Ok(Code::Ok);
        };
        return list(&store, args.format);
    }
    if args.format == Format::Json {
        bail!("`--format json` goes with `--list`");
    }
    let store = Store::open(&home, project)?;
    let mut out = Deferred::default();
    if args.prune {
        let removed = store.prune(Retention::default(), crate::time::now_ms())?;
        writeln!(out, "removed {removed} snapshot(s) past the retention")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    let denied = snapshot::denied(&home, &ctx)?;
    let started = std::time::Instant::now();
    let taken = store.take(&denied, Limits::default(), Reason::Manual, None)?;
    let line = snapshot::said(&taken, Reason::Manual, started.elapsed().as_millis());
    snapshot::record(&home, "snapshot", "snapshot", "snapshot", line.clone());
    writeln!(out, "{}", clean(&line))?;
    out.finish()?;
    Ok(Code::Ok)
}

fn list(store: &Store, format: Format) -> Result<Code> {
    let listed = store.list()?;
    if format == Format::Json {
        render::json(&listed)?;
        return Ok(Code::Ok);
    }
    let mut out = Deferred::default();
    writeln!(
        out,
        "snapshots of {} (newest last):",
        clean(&store.project().display().to_string())
    )?;
    for s in &listed {
        writeln!(
            out,
            "  {}  {}  {:<26} {} files{}",
            s.id,
            crate::time::timestamp(s.ts_ms),
            s.meta.reason.words(),
            s.meta.files,
            s.meta
                .session
                .as_deref()
                .map_or_else(String::new, |r| format!("  {}", clean(r)))
        )?;
        for omitted in &s.meta.left_out {
            writeln!(
                out,
                "      left out: {} ({})",
                clean(&omitted.path),
                omitted.why.words()
            )?;
        }
        if !s.meta.lists_all_left_out() {
            writeln!(
                out,
                "      and {} more left out",
                s.meta.left_out_total - s.meta.left_out.len()
            )?;
        }
    }
    out.finish()?;
    Ok(Code::Ok)
}

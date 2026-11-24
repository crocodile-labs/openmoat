//! `openmoat inventory` (ADR-119): one machine's state for a team, without a
//! hosted service. It reads files only and prints; `--check` compares the
//! machine with a team bundle and exits 1 on drift; `--deliver` sends the
//! OCSF events through the sinks a person configured for it. Nothing leaves
//! the machine otherwise.

use std::io::Write as _;

use anyhow::Result;

use crate::cli::{InventoryArgs, InventoryFormat};
use crate::exit::Code;
use crate::home::Home;
use crate::render::{self, Deferred};

mod check;
mod collect;
mod deliver;
mod ocsf;
#[cfg(test)]
mod tests;

pub fn run(args: &InventoryArgs) -> Result<Code> {
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    if let Some(dir) = &args.check {
        return check_run(&home, &binary, dir, args.format);
    }
    let now = crate::time::now_ms();
    let doc = document(&home, &binary, now)?;
    if args.deliver {
        return deliver::run(&home, &ocsf::events(&doc), now);
    }
    match args.format {
        None | Some(InventoryFormat::Json) => render::json(&doc)?,
        Some(InventoryFormat::Ocsf) => render::json(&ocsf::events(&doc))?,
    }
    Ok(Code::Ok)
}

/// The inventory, redacted, as JSON.
fn document(home: &Home, binary: &std::path::Path, now: i64) -> Result<serde_json::Value> {
    let inventory = collect::collect(home, binary, now)?;
    Ok(collect::redacted(serde_json::to_value(inventory)?))
}

fn check_run(
    home: &Home,
    binary: &std::path::Path,
    dir: &std::path::Path,
    format: Option<InventoryFormat>,
) -> Result<Code> {
    let found = check::run(home, binary, dir)?;
    // Drift is exit 1 (ADR-119): the one code a script can tell from a usage
    // error (64) without reading the output.
    let code = if found.is_empty() {
        Code::Ok
    } else {
        Code::Failed
    };
    if format.is_some() {
        let doc = serde_json::json!({
            "bundle": dir.to_string_lossy(),
            "drift": found,
        });
        render::json(&collect::redacted(doc))?;
        return Ok(code);
    }
    let mut out = Deferred::default();
    if found.is_empty() {
        writeln!(out, "✔ this machine has what the team bundle requires")?;
    }
    for d in &found {
        render::line(&mut out, &format!("✖ {}: {}", d.check, d.detail))?;
    }
    out.finish()?;
    Ok(code)
}

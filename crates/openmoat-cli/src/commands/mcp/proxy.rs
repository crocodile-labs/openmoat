//! `moat mcp proxy --server <name> [--sandbox] -- <command…>`: start the server
//! and relay its stdio through [`Relay`], the MCP gateway (ADR-045), which
//! passes on only what [`Gateway`] lets through.
//!
//! The server's standard error, working directory and environment are the
//! proxy's own, which the agent host set from the definition. With `--sandbox`
//! the server is started as `moat run -- <command…>`, so it runs in the sandbox
//! `moat run` makes from the policy, with network only through OpenMoat's proxy.

use std::io::{self, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context as _, Result};

use super::gate::Gateway;
use crate::cli::McpProxyArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::mcp::relay::{self, Relay, Save};
use crate::mcp::tools::{self, ToolPins};

pub fn run(args: &McpProxyArgs) -> Result<Code> {
    let home = Home::locate()?;
    let path = tools::path(&home, &args.server);
    let pins = ToolPins::load(&path)?;
    // A policy that cannot be read, or one the lock no longer matches, trusts
    // nothing: a new server's tools are held, as they are by default (ADR-032).
    let trust_first_sight = crate::integrity::refuse_drift(&home, "trust first sight").is_ok()
        && home
            .load_policy()
            .is_ok_and(|policy| policy.trust_mcp_first_sight());
    let save: Save = Box::new(move |p: &ToolPins| p.save(&path));
    let gateway = Gateway::new(home, &args.server)?;
    let relay = Arc::new(Relay::new(
        &args.server,
        pins,
        trust_first_sight,
        Box::new(gateway),
        save,
        crate::time::now_ms,
    ));

    let mut child = command(args)?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("starting MCP server `{}`", args.server))?;
    let to_server = Arc::new(Mutex::new(Some(
        child.stdin.take().context("no pipe to the server")?,
    )));
    let from_server = child.stdout.take().context("no pipe from the server")?;
    let host = Arc::new(Mutex::new(Some(io::stdout())));

    // The host's side ends when the agent closes stdin; closing the pipe then
    // tells the server to exit, which ends the server's side below.
    let (relay_in, server_in, host_in) = (
        Arc::clone(&relay),
        Arc::clone(&to_server),
        Arc::clone(&host),
    );
    std::thread::spawn(move || {
        let pumped = relay::pump_host(&relay_in, io::stdin().lock(), &*server_in, &*host_in, &note);
        if let Err(e) = pumped {
            note(&format!("{e:#}"));
        }
        server_in
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    });
    let pumped = relay::pump_server(
        &relay,
        BufReader::new(from_server),
        &*to_server,
        &*host,
        &note,
    );
    if pumped.is_err() {
        // The server's output can no longer be relayed: a server still running
        // would wait on a host that hears nothing more from it.
        let _ = child.kill();
    }
    let status = child.wait().context("waiting for the MCP server")?;
    // The host's thread, still reading stdin, ends with the process.
    pumped?;
    Ok(if status.success() {
        Code::Ok
    } else {
        Code::Failed
    })
}

/// Why the relay dropped something, on the proxy's standard error, which the
/// host shows in its MCP log; the server wrote part of it.
fn note(why: &str) {
    eprintln!("openmoat mcp proxy: {}", crate::render::clean(why));
}

/// The server's command, or `moat run` around it with `--sandbox`.
fn command(args: &McpProxyArgs) -> Result<Command> {
    let (program, rest) = args.command.split_first().context("no server command")?;
    if !args.sandbox {
        let mut command = Command::new(program);
        command.args(rest);
        return Ok(command);
    }
    let moat = std::env::current_exe().context("locating the moat binary")?;
    let mut command = Command::new(moat);
    command.arg("run");
    for write in &args.writes {
        command.arg("--write").arg(write);
    }
    command.arg("--").arg(program).args(rest);
    Ok(command)
}

//! `moat mcp proxy --server <name> [--sandbox] -- <command…>`: start the server
//! and relay its stdio through [`Relay`], the MCP gateway (ADR-045), which
//! passes on only what [`Gateway`] lets through.
//!
//! Before anything starts, the command line it was given must be the one a
//! definition a person accepted gives (`mcp/startup.rs`, ADR-049). When it is
//! not, nothing starts: every request the agent sends is answered with an
//! error naming `openmoat mcp accept`, the refusal is recorded and printed on
//! standard error, and the proxy exits 1 once the agent closes its input.
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
use crate::mcp::startup::{self, Launch, Startup};
use crate::mcp::tools::{self, ToolPins};

pub fn run(args: &McpProxyArgs) -> Result<Code> {
    let home = Home::locate()?;
    let cwd = std::env::current_dir().ok();
    if let Startup::Refuse(why) = startup::check(&home, &Launch::of(args), cwd.as_deref()) {
        return refuse(home, args, &why);
    }
    let path = tools::path(&home, &args.server);
    let pins = ToolPins::load(&path)?;
    // A policy that cannot be read, or one the lock no longer matches, trusts
    // nothing: a new server's tools are held, as they are by default (ADR-032).
    let trust_first_sight = crate::integrity::refuse_drift(&home, "trust first sight").is_ok()
        && home
            .load_policy()
            .is_ok_and(|policy| policy.trust_mcp_first_sight());
    let save: Save = Box::new(move |p: &ToolPins| p.save(&path));
    let gateway = Gateway::new(home, &args.server, args.host)?;
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

/// Start nothing: record and print `why`, and answer the agent with it until
/// it closes the proxy's input.
fn refuse(home: Home, args: &McpProxyArgs, why: &str) -> Result<Code> {
    let message = format!("OpenMoat did not start MCP server `{}`: {why}", args.server);
    note(&message);
    let recorded =
        Gateway::new(home, &args.server, args.host).and_then(|g| g.refused_start(&message));
    if let Err(e) = recorded {
        note(&format!(
            "the refusal could not be recorded in the audit log: {e:#}"
        ));
    }
    let host = Mutex::new(Some(io::stdout()));
    relay::refuse_all(io::stdin().lock(), &host, &crate::render::clean(&message))?;
    Ok(Code::Failed)
}

/// An MCP server is not one of the hooks the relay is for (ADR-075), whatever
/// environment this proxy was started with.
fn without_relay(command: &mut Command) {
    command
        .env_remove(crate::guard_relay::SOCKET_ENV)
        .env_remove(crate::guard_relay::TOKEN_ENV);
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
        without_relay(&mut command);
        return Ok(command);
    }
    let moat = std::env::current_exe().context("locating the moat binary")?;
    let mut command = Command::new(moat);
    without_relay(&mut command);
    command.arg("run");
    for write in &args.writes {
        command.arg("--write").arg(write);
    }
    command.arg("--").arg(program).args(rest);
    Ok(command)
}

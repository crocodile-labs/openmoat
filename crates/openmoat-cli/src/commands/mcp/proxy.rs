//! `moat mcp proxy --server <name> [--sandbox] -- <command…>`: start the server
//! and relay its stdio through [`Relay`].
//!
//! The server's standard error, working directory and environment are the
//! proxy's own, which the agent host set from the definition. With `--sandbox`
//! the server is started as `moat run -- <command…>`, so it runs in the sandbox
//! `moat run` makes from the policy, with network only through OpenMoat's proxy.

use std::io::{self, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context as _, Result};
use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Action, Decision, Verdict};

use crate::cli::McpProxyArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::mcp::relay::{self, Recorder, Relay, Save};
use crate::mcp::tools::{self, ToolPins};

/// Host id of the proxy's audit rows.
const AUDIT_HOST: &str = "mcp-proxy";
/// Rule ids of the proxy's decisions.
const PASSED_RULE: &str = "mcp-proxy";
const HELD_RULE: &str = "mcp-tool-held";

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
    let recorder = Audit::open(&home, &args.server);
    let relay = Arc::new(Relay::new(
        &args.server,
        pins,
        trust_first_sight,
        Box::new(recorder),
        save,
        crate::time::now_ms,
    ));

    let mut child = command(args)?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("starting MCP server `{}`", args.server))?;
    let to_server = child.stdin.take().context("no pipe to the server")?;
    let from_server = child.stdout.take().context("no pipe from the server")?;
    let host = Arc::new(Mutex::new(io::stdout()));

    // The host's side ends when the agent closes stdin; dropping the pipe then
    // tells the server to exit, which ends the server's side below.
    let (relay_in, host_in) = (Arc::clone(&relay), Arc::clone(&host));
    std::thread::spawn(move || {
        if let Err(e) = relay::pump_host(&relay_in, io::stdin().lock(), to_server, &*host_in) {
            eprintln!("openmoat mcp proxy: {e:#}");
        }
    });
    let pumped = relay::pump_server(&relay, BufReader::new(from_server), &*host);
    let status = child.wait().context("waiting for the MCP server")?;
    // The host's thread, still reading stdin, ends with the process.
    pumped?;
    Ok(if status.success() {
        Code::Ok
    } else {
        Code::Failed
    })
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

/// Tool calls in the audit log: host `mcp-proxy`, the tool's full name, and
/// whether the proxy passed it on. Never the arguments: the hook already
/// recorded them, redacted, when the agent made the call.
struct Audit {
    store: Result<Mutex<Store>, String>,
    session: String,
}

impl Audit {
    fn open(home: &Home, server: &str) -> Self {
        let store = Store::open_existing(&home.audit_path())
            .map(Mutex::new)
            .map_err(|e| e.to_string());
        Self {
            store,
            session: format!(
                "mcp-{server}-{}-{}",
                std::process::id(),
                crate::time::now_ms()
            ),
        }
    }
}

impl Recorder for Audit {
    fn record(&self, tool: &str, refused: Option<&str>) -> Result<()> {
        let store = self
            .store
            .as_ref()
            .map_err(|e| anyhow::Error::msg(format!("audit log unavailable: {e}")))?;
        let mut decision = match refused {
            None => Decision::new(Verdict::Allow),
            Some(_) => Decision::new(Verdict::Deny),
        };
        decision.rules.push(
            if refused.is_some() {
                HELD_RULE
            } else {
                PASSED_RULE
            }
            .to_owned(),
        );
        decision.reasons.push(refused.map_or_else(
            || "passed to the server: its definition is the accepted one".to_owned(),
            str::to_owned,
        ));
        let action = Action::mcp(tool);
        let event = NewEvent {
            host: AUDIT_HOST,
            session_id: &self.session,
            call_id: None,
            cwd: None,
            tool,
            action: Some(&action),
            decision: &decision,
            latency_us: 0,
        };
        let store = store.lock().unwrap_or_else(PoisonError::into_inner);
        store.record(&event)?;
        Ok(())
    }
}

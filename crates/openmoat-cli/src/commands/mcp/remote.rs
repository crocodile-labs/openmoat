//! `openmoat mcp remote --server <name> --url <url>`: one remote MCP server
//! (Streamable HTTP) behind the same relay stdio servers go through (ADR-127).
//!
//! The agent starts this as a stdio server. Before anything is sent, the URL
//! must be the one a person pinned with `openmoat mcp login`, the lock must be
//! intact and no deny rule of the policy may name the server's host; otherwise
//! every request is answered with an error naming what to do, the refusal is
//! recorded, and the command exits 1 once the agent closes its input.
//!
//! The relay ([`Relay`]) checks every message both ways exactly as for a
//! stdio server: pinned tools and identity, the hook's decision for each call,
//! result checks. What it passes on toward the server goes to a [`Sink`],
//! which sends each line as a `POST` ([`Transport`]) on a thread of its own and
//! writes the server's answers into a pipe the relay reads as the server's
//! output. A request that cannot be sent is answered with OpenMoat's error.

use std::io::{self, BufReader, PipeWriter, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, Result};
use openmoat_core::{Action, CompiledPolicy, Verdict, rule_id};

use super::gate::Gateway;
use crate::cli::McpRemoteArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::mcp::relay::{self, Relay, Save};
use crate::mcp::remote::{self, transport::Transport};
use crate::mcp::tools::{self, ToolPins};

/// How long one request may wait for its answer: a tool call may be slow.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

pub fn run(args: &McpRemoteArgs) -> Result<Code> {
    let home = Home::locate()?;
    let transport = match admit(&home, args) {
        Ok(transport) => Arc::new(transport),
        Err(why) => return refuse(home, args, &format!("{why:#}")),
    };
    let path = tools::path(&home, &args.server);
    let pins = ToolPins::load(&path)?;
    let policy = home.load_policy()?;
    let save: Save = Box::new(move |p: &ToolPins| p.save(&path));
    let gateway = Gateway::new(home, &args.server, args.host)?;
    let relay = Arc::new(
        Relay::new(
            &args.server,
            pins,
            policy.trust_mcp_first_sight(),
            Box::new(gateway),
            save,
            crate::time::now_ms,
        )
        .allowing_sampling(policy.allow_mcp_sampling()),
    );
    let (from_server, to_relay) = io::pipe().context("making the gateway's pipe")?;
    let sink = Sink {
        transport,
        out: Arc::new(Mutex::new(to_relay)),
        line: Vec::new(),
    };
    let to_server = Arc::new(Mutex::new(Some(sink)));
    let host = Arc::new(Mutex::new(Some(io::stdout())));
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
        // Dropping the sink drops its end of the pipe; once the requests in
        // flight are answered the relay reads the end of the server's output.
        server_in
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    });
    relay::pump_server(
        &relay,
        BufReader::new(from_server),
        &*to_server,
        &*host,
        &note,
    )?;
    Ok(Code::Ok)
}

/// The transport to the server `args` names, once its URL, the lock and the
/// policy let it be reached.
fn admit(home: &Home, args: &McpRemoteArgs) -> Result<Transport> {
    let record = remote::admitted(home, &args.server, &args.url)?;
    crate::integrity::refuse_drift(home, "reach a remote MCP server")?;
    let policy = home.load_policy()?;
    let ctx = crate::context::eval_context(home, None, None)?;
    let compiled = CompiledPolicy::compile(&policy, &ctx)?;
    let endpoint = remote::endpoint(&args.url)?;
    // A deny rule naming the host refuses it, as for a link the server asks
    // the person to open (ADR-114); the catch-all for unlisted hosts does not:
    // a person named this server.
    let decision = compiled.decide(&Action::Net {
        url: remote::origin(&endpoint),
    });
    let named_deny = decision.verdict == Verdict::Deny
        && decision
            .rules
            .iter()
            .any(|rule| rule != rule_id::DEFAULT && !rule.starts_with(rule_id::DEFAULT_PREFIX));
    if named_deny {
        anyhow::bail!(
            "the policy denies connections to {} ({})",
            endpoint.host,
            decision.rules.join(", ")
        );
    }
    let token = record
        .token
        .as_ref()
        .map(|t| zeroize::Zeroizing::new(t.clone()));
    Transport::new(
        endpoint,
        token,
        &policy,
        ctx,
        Box::new(openmoat_proxy::SystemResolver),
        REQUEST_TIMEOUT,
    )
}

/// Send nothing: record and print `why`, and answer the agent with it until
/// it closes the gateway's input.
fn refuse(home: Home, args: &McpRemoteArgs, why: &str) -> Result<Code> {
    let message = format!(
        "OpenMoat did not connect to remote MCP server `{}`: {why}",
        args.server
    );
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

/// Why the gateway dropped something, on its standard error, which the host
/// shows in its MCP log.
fn note(why: &str) {
    eprintln!("openmoat mcp remote: {}", crate::render::clean(why));
}

/// Where the relay writes what goes to the server: each whole line is sent on
/// a thread of its own, and its answers are written to the relay's side.
struct Sink {
    transport: Arc<Transport>,
    out: Arc<Mutex<PipeWriter>>,
    line: Vec<u8>,
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.line.extend_from_slice(bytes);
        while let Some(end) = self.line.iter().position(|b| *b == b'\n') {
            let rest = self.line.split_off(end + 1);
            let line = std::mem::replace(&mut self.line, rest);
            let text = String::from_utf8_lossy(&line).trim().to_owned();
            if text.is_empty() {
                continue;
            }
            let (transport, out) = (Arc::clone(&self.transport), Arc::clone(&self.out));
            std::thread::spawn(move || deliver(&transport, &out, &text));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Send `message` and write the answers for the relay; a request that could
/// not be sent is answered with OpenMoat's error instead, so the agent does
/// not wait for it.
fn deliver(transport: &Transport, out: &Mutex<PipeWriter>, message: &str) {
    let answers = match transport.send(message) {
        Ok(answers) => answers,
        Err(e) => {
            let why = format!("{e:#}");
            note(&why);
            remote::failed_answer(message, &why).into_iter().collect()
        }
    };
    let mut out = out.lock().unwrap_or_else(PoisonError::into_inner);
    for answer in answers {
        let line = answer.replace(['\r', '\n'], " ");
        if writeln!(out, "{line}").is_err() {
            return;
        }
    }
}

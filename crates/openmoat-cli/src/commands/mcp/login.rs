//! `openmoat mcp login <server> --url <url>`: a person names a remote MCP
//! server for `openmoat mcp remote` (ADR-127). Its URL is pinned and the token
//! they type is kept owner-only in OpenMoat's state directory, which the
//! agent cannot read; the agent's configuration gets only the command that
//! starts the gateway. `--forget` removes both.
//!
//! Before asking for the token, the server's sign-in metadata (RFC 9728) is
//! read, over `https` with every address checked, to name the authorization
//! servers that issue its tokens. Signing in through them (the OAuth
//! authorization code flow) is not done here: the person gets a token there
//! and types it.

use std::io::Write as _;
use std::time::Duration;

use anyhow::{Context as _, Result};

use crate::cli::McpLoginArgs;
use crate::exit::Code;
use crate::mcp::remote::{self, Record, discovery, transport::Transport};
use crate::render::Deferred;

/// How long reading the sign-in metadata may take.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Where the commands are explained.
const DOCS: &str = "docs/USAGE.md \"Remote MCP servers\"";

pub fn run(args: &McpLoginArgs) -> Result<Code> {
    let home = super::person_only("login")?;
    let endpoint = remote::endpoint(&args.url).with_context(|| {
        format!(
            "for example `openmoat mcp login {} --url https://mcp.example.com/mcp` ({DOCS})",
            args.server
        )
    })?;
    let mut out = Deferred::default();
    if args.forget {
        let path = remote::path(&home, &args.server);
        match std::fs::remove_file(&path) {
            Ok(()) => writeln!(out, "forgot remote MCP server `{}`", args.server)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                writeln!(out, "no remote MCP server `{}` was named", args.server)?;
            }
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
        out.finish()?;
        return Ok(Code::Ok);
    }
    let policy = home.load_policy()?;
    let ctx = crate::context::eval_context(&home, None, None)?;
    let probe = Transport::new(
        endpoint.clone(),
        None,
        &policy,
        ctx,
        Box::new(openmoat_proxy::SystemResolver),
        DISCOVERY_TIMEOUT,
    )?;
    match discover(&probe, &endpoint) {
        Ok(Some(metadata)) if !metadata.authorization_servers.is_empty() => writeln!(
            out,
            "{} issues tokens through: {}",
            remote::origin(&endpoint),
            metadata.authorization_servers.join(", ")
        )?,
        Ok(_) => writeln!(
            out,
            "{} names no authorization server",
            remote::origin(&endpoint)
        )?,
        Err(e) => writeln!(out, "its sign-in metadata could not be read: {e:#}")?,
    }
    out.finish()?;
    let token = if args.no_token {
        None
    } else {
        let typed = crate::terminal::read_secret(&format!(
            "Token for `{}` (hidden; empty for a server without sign-in): ",
            args.server
        ))?;
        (!typed.trim().is_empty()).then(|| typed.trim().to_owned())
    };
    let mut out = Deferred::default();
    writeln!(
        out,
        "OpenMoat will reach `{}` only at {}{}; the agent never holds the token.",
        args.server,
        remote::origin(&endpoint),
        if token.is_some() {
            ", adding the token to each request"
        } else {
            ", with no token"
        }
    )?;
    if !super::super::edit::confirm(&mut out, "Pin it? [y/N] ")? {
        writeln!(out, "nothing was pinned")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    // Pinning a server lets the agent's calls reach it: the gate asks (ADR-117).
    let pass = crate::gate::pass(&home, "openmoat mcp login")?;
    Record {
        url: args.url.clone(),
        token,
    }
    .save(&home, &args.server)?;
    pass.record(
        &home,
        &format!("pinned remote MCP server {}", args.server),
        &[remote::origin(&endpoint)],
    );
    writeln!(
        out,
        "Pinned. Point the agent's configuration for `{}` at the gateway:\n  \
         {{\"command\": \"openmoat\", \"args\": [\"mcp\", \"remote\", \"--server\", \"{}\", \
         \"--url\", \"{}\"]}}\nUndo with `openmoat mcp login {} --url {} --forget` ({DOCS}).",
        args.server, args.server, args.url, args.server, args.url
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// The server's sign-in metadata, if it publishes any.
fn discover(
    probe: &Transport,
    endpoint: &openmoat_proxy::Endpoint,
) -> Result<Option<discovery::Metadata>> {
    if endpoint.scheme != openmoat_proxy::Scheme::Https {
        return Ok(None);
    }
    let reply = probe.get(&discovery::well_known(endpoint)?)?;
    match reply.status {
        200 => Ok(Some(discovery::check(endpoint, &reply.body)?)),
        404 => Ok(None),
        status => anyhow::bail!("HTTP {status}"),
    }
}

//! `moat mcp …` grammar.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Show what changed in the agents' MCP server definitions, and in the tools of
    /// servers run through `openmoat mcp proxy`, and ask before accepting it. Until then,
    /// the changed server's tool calls are refused. Refused unless run from an
    /// interactive terminal, and over a drifted lock.
    Accept(McpAcceptArgs),
    /// Run one stdio MCP server through OpenMoat (started by the agent from its
    /// configuration, not by people): pin each tool's whole definition (title,
    /// description, input and output schemas, annotations and every other field), hide a
    /// tool whose definition changed until `openmoat mcp accept`, and record every tool
    /// call in the audit log.
    Proxy(McpProxyArgs),
    /// Point stdio MCP servers in the agents' user configuration at `openmoat mcp proxy`,
    /// backing the files up first. Refused unless run from an interactive terminal.
    Wrap(McpWrapArgs),
    /// Point wrapped MCP servers back at their own command. Refused unless run from an
    /// interactive terminal.
    Unwrap(McpUnwrapArgs),
}

#[derive(Debug, Args)]
pub struct McpAcceptArgs {
    /// Only this server's changes. Defaults to every change found.
    pub server: Option<String>,
}

#[derive(Debug, Args)]
pub struct McpProxyArgs {
    /// The server's name in the agent's configuration.
    #[arg(long)]
    pub server: String,

    /// Start the server under `openmoat run`: in a sandbox made from the policy, with
    /// network only through OpenMoat's proxy (macOS, Linux). Not inside `openmoat run`:
    /// sandboxes do not nest.
    #[arg(long)]
    pub sandbox: bool,

    /// With --sandbox: a file or directory the server may also write (`openmoat run --write`).
    #[arg(long = "write", value_name = "PATH", requires = "sandbox")]
    pub writes: Vec<PathBuf>,

    /// The server's command and arguments, after `--`.
    #[arg(required = true, last = true, value_name = "COMMAND")]
    pub command: Vec<std::ffi::OsString>,
}

#[derive(Debug, Args)]
pub struct McpWrapArgs {
    /// Servers to wrap, by name. Defaults to every stdio server found.
    pub servers: Vec<String>,

    /// Also start each server under `openmoat run` (`openmoat mcp proxy --sandbox`).
    #[arg(long)]
    pub sandbox: bool,

    /// Print what would change without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct McpUnwrapArgs {
    /// Servers to unwrap, by name. Defaults to every wrapped server.
    pub servers: Vec<String>,
}

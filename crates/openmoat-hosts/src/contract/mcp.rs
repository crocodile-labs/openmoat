//! Where a host reads its MCP server definitions, how it lays them out, and
//! how it names their tools. The CLI finds and reads the files and keeps the
//! pins; what is here is pure.

use std::fmt::Debug;

use serde_json::{Map, Value};

/// Where a host reads its MCP server definitions. A file that does not exist
/// lists no servers.
#[derive(Debug)]
#[non_exhaustive]
pub struct McpSpec {
    /// The user-level file, in or beside the host's configuration.
    pub user_file: McpFile,
    /// How that file lays out its servers.
    pub user_reader: &'static dyn McpReader,
    /// A project's files, relative to the working directory and each
    /// directory above it up to the project root, and their layout; empty
    /// when the host documents none.
    pub project_files: &'static [(&'static str, &'static dyn McpReader)],
    /// How the host names a server's tools in its hook payloads.
    pub tool_names: &'static dyn McpNames,
}

/// Where a host's user-level MCP server file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpFile {
    /// The file the hook goes into, wherever the host's configuration puts it.
    HookFile,
    /// The file of this name beside the hook file.
    BesideHookFile(&'static str),
    /// The file of this name in the configuration directory, whose hook file
    /// is in a subdirectory of it (GitHub Copilot CLI's `mcp-config.json`
    /// beside `hooks/`, pi's `mcp.json` beside `extensions/`).
    InConfigDir(&'static str),
    /// Each file of these names in the configuration directory, all of which
    /// the host reads and merges (OpenCode's `config.json`, `opencode.json`
    /// and `opencode.jsonc`).
    EachInConfigDir(&'static [&'static str]),
    /// The file of this name in the home directory while the configuration
    /// directory is the default `~/<dir_name>`, inside the configuration
    /// directory otherwise (Claude Code's `~/.claude.json`).
    BesideDefaultDir(&'static str),
}

/// The syntax of a file of MCP servers. The CLI parses each into JSON (and
/// writes each back), so TOML and JSON definitions pin alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpSyntax {
    /// JSON; an empty file lists no servers.
    Json,
    /// TOML, read as JSON.
    Toml,
    /// JSON5 (OpenClaw), written back as JSON; an empty file lists no servers.
    /// Also JSON with comments and trailing commas (OpenCode's JSONC), which
    /// JSON5 reads.
    Json5,
}

/// One server definition as a file lays it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServer {
    /// The JSON pointer of the entry inside the file (`/mcpServers/github`).
    pub pointer: String,
    /// The server's name, as the file spells it.
    pub name: String,
    /// The definition.
    pub entry: Value,
}

/// How a file lays out its MCP servers: the server list OpenMoat pins.
pub trait McpReader: Sync + Debug {
    /// The file's syntax.
    fn syntax(&self) -> McpSyntax;
    /// The servers `doc`, the file parsed as JSON, defines; `Err` with the
    /// reason when the file hides servers OpenMoat cannot see.
    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String>;
}

/// How a host names an MCP server's tools in the hook payload, so a tool call
/// can be traced to the server definition it came from. Every host's names
/// also match `mcp__<server>__…` (the CLI checks that first): matching too
/// much only holds back another server's tools while one is unaccepted.
pub trait McpNames: Sync + Debug {
    /// Whether `tool` is one of server `server`'s tools beyond the
    /// `mcp__<server>__…` forms.
    fn tool_of(&self, tool: &str, server: &str) -> bool;
}

/// `{"mcpServers": {"<name>": {...}}}` in JSON: `.mcp.json`, Cursor's
/// `mcp.json`, Gemini CLI's `settings.json`.
#[derive(Debug)]
pub(crate) struct McpServersJson;

impl McpReader for McpServersJson {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Json
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        Ok(servers_at(doc, "mcpServers", "/mcpServers"))
    }
}

/// `mcp__<server>__<tool>`, the server's name as written or with every
/// character but letters, digits, `_` and `-` as `_` (Claude Code), which the
/// CLI's own check covers.
#[derive(Debug)]
pub(crate) struct Prefixed;

impl McpNames for Prefixed {
    fn tool_of(&self, _tool: &str, _server: &str) -> bool {
        false
    }
}

/// The servers in the object at `key` of `value`, their pointers under `at`.
pub(crate) fn servers_at(value: &Value, key: &str, at: &str) -> Vec<McpServer> {
    value
        .get(key)
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(Map::iter)
        .map(|(name, entry)| server(format!("{at}/{}", escape(name)), name, entry))
        .collect()
}

/// A server at `pointer`.
pub(crate) fn server(pointer: String, name: &str, entry: &Value) -> McpServer {
    McpServer {
        pointer,
        name: name.to_owned(),
        entry: entry.clone(),
    }
}

/// A JSON pointer token (RFC 6901): `~` and `/` escaped.
#[must_use]
pub fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// `name` with every character but ASCII letters, digits and those `keep`
/// allows as `with`.
pub(crate) fn spelled(name: &str, keep: impl Fn(char) -> bool, with: char) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || keep(c) {
                c
            } else {
                with
            }
        })
        .collect()
}

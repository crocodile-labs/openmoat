//! Where each agent host reads its MCP server definitions, and reading them.
//!
//! - Claude Code: `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json` when that is
//!   set) with `mcpServers` for the user and `projects.<path>.mcpServers` for each
//!   project's local servers, and a project's `.mcp.json`.
//! - Codex: `config.toml` beside its hook file (`[mcp_servers.<name>]`), and a
//!   project's `.codex/config.toml`.
//! - Cursor: `mcp.json` beside its hook file, and a project's `.cursor/mcp.json`.
//! - OpenClaw: `mcp.servers.<name>` in `openclaw.json` (JSON5), wherever
//!   `OPENCLAW_CONFIG_PATH` or the state directory puts it
//!   (<https://docs.openclaw.ai/tools/mcp>, "Server definitions live under
//!   `mcp.servers`"). The lock pins the rest of that file whole
//!   (`integrity/digest.rs`). Plugin bundles bring their own `.mcp.json`; they
//!   are plugin code, which `runs-later` holds for review before an agent writes.
//! - GitHub Copilot CLI: `mcp-config.json` in its configuration directory, and a
//!   project's `.mcp.json` and `.github/mcp.json`, wrapped in `mcpServers` or bare.
//! - pi: `mcp.json` in its agent directory, and a project's `.pi/mcp.json`.
//! - Gemini CLI: `mcpServers` in its `settings.json`, the user's and a project's.
//! - OpenCode: `mcp.<name>` in its `config.json`, `opencode.json` and
//!   `opencode.jsonc` (JSON with comments, read as JSON5), and a project's
//!   `opencode.json[c]` and `.opencode/opencode.json[c]`.
//!
//! Project files are looked for in the working directory and each directory above
//! it up to the project root. A file that does not exist lists no servers.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use openmoat_hosts::{Host, McpFile, McpReader, McpSyntax};
use serde_json::{Map, Value};
use toml_edit::{DocumentMut, Item};

use crate::home::{Home, user_home};
use crate::install::HostConfig;

/// A file one host reads MCP servers from.
#[derive(Debug, Clone)]
pub struct Source {
    pub host: Host,
    pub path: PathBuf,
    /// How the file lays out its servers.
    pub reader: &'static dyn McpReader,
    /// A user-level file (in the host's configuration), not a project's.
    pub user: bool,
}

/// One server definition as its host reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// `<file>#<pointer>`, the lock's key for this definition.
    pub id: String,
    pub host: Host,
    pub file: PathBuf,
    /// The JSON pointer of the entry inside the file (`/mcpServers/github`).
    pub pointer: String,
    pub name: String,
    pub entry: Value,
}

/// What reading a set of sources found.
#[derive(Debug, Default)]
pub struct Scan {
    pub servers: Vec<Server>,
    /// Files that exist but could not be read or parsed, with the reason.
    pub unreadable: Vec<(PathBuf, String)>,
    /// Every file looked at, present or not, so a pin from one of them whose
    /// entry is gone counts as removed.
    pub scanned: Vec<PathBuf>,
}

/// The files `host` reads servers from, for a session in `cwd` (none of a
/// project's when `cwd` is `None` or in no project).
pub fn sources(home: &Home, host: Host, cwd: Option<&Path>) -> Result<Vec<Source>> {
    let Some(mcp) = &host.spec().mcp else {
        return Ok(Vec::new());
    };
    let mut out: Vec<Source> = user_files(home, host, mcp.user_file)?
        .into_iter()
        .map(|path| Source {
            host,
            path,
            reader: mcp.user_reader,
            user: true,
        })
        .collect();
    if let Some(cwd) = cwd
        && !mcp.project_files.is_empty()
    {
        for dir in project_dirs(cwd)? {
            for (relative, reader) in mcp.project_files {
                out.push(Source {
                    host,
                    path: dir.join(relative),
                    reader: *reader,
                    user: false,
                });
            }
        }
    }
    Ok(out)
}

/// Where `file`, `host`'s user-level MCP server file, can be. Claude Code reads
/// `.claude.json` from the home directory unless `CLAUDE_CONFIG_DIR` is set, and
/// from inside that directory when it is, even when it names the default
/// `~/.claude`. A moved directory is always named by the variable; for the
/// default one the environment `moat` runs in need not be the agent's, so both
/// files are read.
fn user_files(home: &Home, host: Host, file: McpFile) -> Result<Vec<PathBuf>> {
    let config = HostConfig::for_host(home, host)?;
    Ok(match file {
        McpFile::HookFile => vec![config.settings_path],
        McpFile::BesideHookFile(name) => vec![config.settings_path.with_file_name(name)],
        McpFile::InConfigDir(name) => vec![config.dir().join(name)],
        McpFile::EachInConfigDir(names) => names.iter().map(|n| config.dir().join(n)).collect(),
        McpFile::BesideDefaultDir(name) => {
            let user = user_home()?;
            let default = host.spec().install.as_ref().map(|i| user.join(i.dir_name));
            let inside = config.dir().join(name);
            if default.is_some_and(|d| config.dir() == d) {
                vec![user.join(name), inside]
            } else {
                vec![inside]
            }
        }
    })
}

/// `cwd` and each directory above it up to its project root; none outside a project.
/// The directory is taken with its links resolved: `openmoat init` gets it
/// from the operating system that way, a hook gets it as the agent spelt it
/// (`/var/…` and `/private/var/…` on macOS), and both must name the same
/// project file for its pins to be found.
fn project_dirs(cwd: &Path) -> Result<Vec<PathBuf>> {
    let (cwd, home) = (resolved(cwd), resolved(&user_home()?));
    let cwd = cwd.as_path();
    let Some(root) = crate::project::root_of(cwd, &home) else {
        return Ok(Vec::new());
    };
    Ok(cwd
        .ancestors()
        .take_while(|dir| dir.starts_with(&root))
        .map(Path::to_path_buf)
        .collect())
}

/// `path` with its links resolved on Unix; as given when it cannot be, and on
/// Windows, whose resolved form (`\\?\C:\…`) would differ from every other
/// spelling of the path OpenMoat records.
fn resolved(path: &Path) -> PathBuf {
    if cfg!(unix) {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    }
}

/// Read every server `sources` define.
pub fn scan(sources: &[Source]) -> Scan {
    let mut found = Scan::default();
    for source in sources {
        found.scanned.push(source.path.clone());
        let text = match fs::read_to_string(&source.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                found.unreadable.push((source.path.clone(), e.to_string()));
                continue;
            }
        };
        match parse(source, &text) {
            Ok(servers) => found.servers.extend(servers),
            Err(e) => found
                .unreadable
                .push((source.path.clone(), format!("{e:#}"))),
        }
    }
    found
}

/// The servers `text`, the contents of `source`, defines.
pub fn parse(source: &Source, text: &str) -> Result<Vec<Server>> {
    let doc = match source.reader.syntax() {
        McpSyntax::Json if text.trim().is_empty() => Value::Object(Map::new()),
        McpSyntax::Json => serde_json::from_str(text).context("parsing JSON")?,
        McpSyntax::Toml => {
            let doc: DocumentMut = text.parse().context("parsing TOML")?;
            toml_to_json(doc.as_item())
        }
        McpSyntax::Json5 => {
            crate::json5::parse_or_empty(text)
                .context("parsing JSON5")?
                .value
        }
        McpSyntax::Yaml => openmoat_hosts::yaml_hooks::parse(text)
            .map_err(anyhow::Error::msg)
            .context("parsing YAML")?,
    };
    let servers = source.reader.servers(&doc).map_err(anyhow::Error::msg)?;
    Ok(servers
        .into_iter()
        .map(|server| Server {
            id: format!("{}#{}", source.path.display(), server.pointer),
            host: source.host,
            file: source.path.clone(),
            pointer: server.pointer,
            name: server.name,
            entry: server.entry,
        })
        .collect())
}

/// A TOML item as JSON, so TOML and JSON definitions pin alike.
pub fn toml_to_json(item: &Item) -> Value {
    match item {
        Item::None => Value::Null,
        Item::Value(value) => toml_value(value),
        Item::Table(table) => Value::Object(
            table
                .iter()
                .map(|(k, v)| (k.to_owned(), toml_to_json(v)))
                .collect(),
        ),
        Item::ArrayOfTables(tables) => Value::Array(
            tables
                .iter()
                .map(|t| toml_to_json(&Item::Table(t.clone())))
                .collect(),
        ),
    }
}

fn toml_value(value: &toml_edit::Value) -> Value {
    use toml_edit::Value as T;
    match value {
        T::String(s) => Value::String(s.value().clone()),
        T::Integer(i) => Value::from(*i.value()),
        T::Float(f) => serde_json::Number::from_f64(*f.value())
            .map_or_else(|| Value::String(f.value().to_string()), Value::Number),
        T::Boolean(b) => Value::Bool(*b.value()),
        T::Datetime(d) => Value::String(d.value().to_string()),
        T::Array(items) => Value::Array(items.iter().map(toml_value).collect()),
        T::InlineTable(table) => Value::Object(
            table
                .iter()
                .map(|(k, v)| (k.to_owned(), toml_value(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests;

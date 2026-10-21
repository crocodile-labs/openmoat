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
//!   are plugin code, which `runs-later` asks before an agent writes.
//!
//! Project files are looked for in the working directory and each directory above
//! it up to the project root. A file that does not exist lists no servers.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use openmoat_hosts::{Host, McpFile};
use serde_json::{Map, Value};
use toml_edit::{DocumentMut, Item};

use crate::home::{Home, user_home};
use crate::install::HostConfig;

/// How a file lays out its servers.
pub use openmoat_hosts::McpLayout as Layout;

/// A file one host reads MCP servers from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub host: Host,
    pub path: PathBuf,
    pub layout: Layout,
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
            layout: mcp.user_layout,
            user: true,
        })
        .collect();
    if let (Some((relative, layout)), Some(cwd)) = (mcp.project_file, cwd) {
        for dir in project_dirs(cwd)? {
            out.push(Source {
                host,
                path: dir.join(relative),
                layout,
                user: false,
            });
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
    let mut out = Vec::new();
    let mut add = |pointer: String, name: &str, entry: &Value| {
        out.push(Server {
            id: format!("{}#{pointer}", source.path.display()),
            host: source.host,
            file: source.path.clone(),
            pointer,
            name: name.to_owned(),
            entry: entry.clone(),
        });
    };
    match source.layout {
        Layout::Json | Layout::ClaudeJson => {
            if text.trim().is_empty() {
                return Ok(Vec::new());
            }
            let root: Value = serde_json::from_str(text).context("parsing JSON")?;
            for (name, entry) in servers_in(&root, "mcpServers") {
                add(format!("/mcpServers/{}", escape(name)), name, entry);
            }
            if source.layout == Layout::ClaudeJson
                && let Some(projects) = root.get("projects").and_then(Value::as_object)
            {
                for (project, settings) in projects {
                    for (name, entry) in servers_in(settings, "mcpServers") {
                        let pointer =
                            format!("/projects/{}/mcpServers/{}", escape(project), escape(name));
                        add(pointer, name, entry);
                    }
                }
            }
        }
        Layout::Toml => {
            let doc: DocumentMut = text.parse().context("parsing TOML")?;
            if let Some(Value::Object(servers)) = doc.get("mcp_servers").map(toml_to_json) {
                for (name, entry) in &servers {
                    add(format!("/mcp_servers/{}", escape(name)), name, entry);
                }
            }
        }
        Layout::OpenClaw => {
            let root = crate::install::openclaw::parse(text)
                .context("parsing JSON5")?
                .value;
            refuse_include(&root)?;
            if let Some(servers) = root.pointer("/mcp/servers").and_then(Value::as_object) {
                for (name, entry) in servers {
                    add(format!("/mcp/servers/{}", escape(name)), name, entry);
                }
            }
        }
    }
    Ok(out)
}

/// OpenClaw merges in the files an `$include` key names; one where MCP
/// servers may come from hides which servers OpenClaw starts.
fn refuse_include(root: &Value) -> Result<()> {
    for at in ["", "/mcp", "/mcp/servers"] {
        if root
            .pointer(at)
            .and_then(Value::as_object)
            .is_some_and(|o| o.contains_key("$include"))
        {
            let place = if at.is_empty() { "the top level" } else { at };
            anyhow::bail!(
                "`$include` at {place} may bring MCP servers from another file, which OpenMoat \
                 does not read; move `mcp.servers` into this file"
            );
        }
    }
    Ok(())
}

/// The `(name, entry)` pairs of the object at `key` in `value`.
fn servers_in<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = (&'a String, &'a Value)> {
    value
        .get(key)
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(Map::iter)
}

/// A JSON pointer token (RFC 6901): `~` and `/` escaped.
pub fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
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
mod tests {
    use super::*;

    fn source(layout: Layout) -> Source {
        Source {
            host: Host::ClaudeCode,
            path: PathBuf::from("/h/.claude.json"),
            layout,
            user: true,
        }
    }

    #[test]
    fn claude_json_lists_user_and_project_servers() {
        let text = r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh"]}},
            "projects": {"/p/a": {"mcpServers": {"db/x": {"command": "db"}}}, "/p/b": {}},
            "numStartups": 4}"#;
        let servers = parse(&source(Layout::ClaudeJson), text).unwrap();
        let ids: Vec<&str> = servers.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "/h/.claude.json#/mcpServers/gh",
                "/h/.claude.json#/projects/~1p~1a/mcpServers/db~1x"
            ]
        );
        assert_eq!(servers[1].name, "db/x");
        assert_eq!(servers[0].entry["args"][1], "gh");
    }

    #[test]
    fn a_plain_json_file_has_no_project_servers() {
        let text = r#"{"mcpServers": {"a": {"url": "https://x"}}, "projects": {"/p": {"mcpServers": {"b": {}}}}}"#;
        let servers = parse(&source(Layout::Json), text).unwrap();
        assert_eq!(servers.len(), 1);
        assert!(parse(&source(Layout::Json), "  ").unwrap().is_empty());
        assert!(parse(&source(Layout::Json), "{").is_err());
    }

    #[test]
    fn codex_toml_servers_read_as_json() {
        let text = "model = \"x\"\n[mcp_servers.docs]\ncommand = \"docs-server\"\nargs = [\"--port\", \"4000\"]\nenv = { TOKEN = \"t\" }\nstartup_timeout_sec = 20\n";
        let servers = parse(&source(Layout::Toml), text).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].pointer, "/mcp_servers/docs");
        assert_eq!(
            servers[0].entry,
            serde_json::json!({"command": "docs-server", "args": ["--port", "4000"],
                "env": {"TOKEN": "t"}, "startup_timeout_sec": 20})
        );
    }

    #[test]
    fn openclaw_servers_are_read_from_json5() {
        let openclaw = Source {
            host: Host::OpenClaw,
            path: PathBuf::from("/h/.openclaw/openclaw.json"),
            ..source(Layout::OpenClaw)
        };
        let text = "// mine\n{ mcp: { servers: { 'my/docs': { url: 'https://x/mcp', \
                    transport: 'streamable-http', }, }, }, gateway: { port: 1 } }";
        let servers = parse(&openclaw, text).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers[0].id,
            "/h/.openclaw/openclaw.json#/mcp/servers/my~1docs"
        );
        assert_eq!(servers[0].name, "my/docs");
        assert_eq!(servers[0].entry["transport"], "streamable-http");
        assert!(parse(&openclaw, "").unwrap().is_empty());
        assert!(parse(&openclaw, "{ gateway: {} }").unwrap().is_empty());
        for include in [
            r#"{"$include": "./more.json5"}"#,
            r#"{"mcp": {"servers": {"$include": ["./a.json5"]}}}"#,
        ] {
            let refused = parse(&openclaw, include).unwrap_err().to_string();
            assert!(refused.contains("$include"), "{refused}");
        }
        // An `$include` elsewhere cannot bring servers.
        assert!(parse(&openclaw, r#"{"agents": {"$include": "./a.json5"}}"#).is_ok());
    }

    #[test]
    fn scan_skips_missing_files_and_reports_broken_ones() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("mcp.json");
        fs::write(&broken, "{not json").unwrap();
        let missing = dir.path().join("absent.json");
        let sources: Vec<Source> = [&broken, &missing]
            .into_iter()
            .map(|p| Source {
                path: p.clone(),
                ..source(Layout::Json)
            })
            .collect();
        let found = scan(&sources);
        assert!(found.servers.is_empty());
        assert_eq!(found.scanned.len(), 2);
        assert_eq!(found.unreadable.len(), 1);
        assert_eq!(found.unreadable[0].0, broken);
    }
}

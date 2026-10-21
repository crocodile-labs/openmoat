//! `moat mcp wrap` and `unwrap`: point a stdio server's definition at
//! `moat mcp proxy`, and back.
//!
//! Wrapping replaces `command` and `args` and nothing else:
//! `{"command": "npx", "args": ["-y", "pkg"]}` becomes
//! `{"command": "<moat>", "args": ["mcp", "proxy", "--server", "<name>", "--", "npx", "-y", "pkg"]}`.
//! The original stays in the arguments after `--`, so unwrapping needs no other
//! record, and `env`, `cwd` and the rest stay as they were. Only user-level files
//! are changed (`~/.claude.json`, Cursor's `mcp.json`, Codex's `config.toml`,
//! OpenClaw's `openclaw.json`, Copilot's `mcp-config.json`, pi's `mcp.json`,
//! Gemini CLI's `settings.json`): a
//! project's `.mcp.json` is shared through its repository, where the path of this
//! machine's `moat` means nothing. Each file is backed up before its first change,
//! and `hosts.json` records every wrapped definition for `moat uninstall`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use toml_edit::{Array, DocumentMut, value};

use super::servers::{self, Layout, Server, Source};
use crate::home::{Home, write_private};
use crate::install::Recorded;

/// Suffix of the copy taken before the first wrap changes a file.
pub const MCP_BACKUP: &str = "moat-mcp-backup";

/// One definition `moat mcp wrap` changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wrapped {
    pub host: String,
    pub file: PathBuf,
    pub pointer: String,
    pub name: String,
}

/// What wrapping or unwrapping did to one definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub server: Server,
    /// The definition as written.
    pub entry: Value,
}

/// `entry`'s `command` and `args` when it is a stdio server: a `command`
/// string, and no `type` other than `stdio` (`local` in GitHub Copilot CLI's
/// `mcp-config.json`).
fn stdio(entry: &Value) -> Option<(String, Vec<String>)> {
    if entry
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| t != "stdio" && t != "local")
    {
        return None;
    }
    let command = entry.get("command")?.as_str()?.to_owned();
    let args = match entry.get("args") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|a| a.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    Some((command, args))
}

/// The original command and arguments of a wrapped definition.
fn original(command: &str, args: &[String]) -> Option<(String, Vec<String>)> {
    let program = Path::new(command).file_stem()?.to_str()?;
    // `moat` is the name a wrap made before the rename wrote.
    if !matches!(program, "openmoat" | "moat") || args.get(..2)? != ["mcp", "proxy"] {
        return None;
    }
    let split = args.iter().position(|a| a == "--")?;
    let (first, rest) = args.get(split + 1..)?.split_first()?;
    Some((first.clone(), rest.to_vec()))
}

/// `entry` running through the proxy at `binary`; `None` when it is not a
/// stdio server or is wrapped already.
pub fn wrapped(entry: &Value, binary: &Path, name: &str, sandbox: bool) -> Option<Value> {
    let (command, args) = stdio(entry)?;
    if original(&command, &args).is_some() {
        return None;
    }
    let mut proxy: Vec<String> = ["mcp", "proxy", "--server", name]
        .map(str::to_owned)
        .to_vec();
    if sandbox {
        proxy.push("--sandbox".to_owned());
    }
    proxy.push("--".to_owned());
    proxy.push(command);
    proxy.extend(args);
    let mut out = entry.clone();
    out["command"] = Value::String(binary.display().to_string());
    out["args"] = Value::from(proxy);
    Some(out)
}

/// `entry` as it was before [`wrapped`]; `None` when it is not wrapped.
pub fn unwrapped(entry: &Value) -> Option<Value> {
    let (command, args) = stdio(entry)?;
    let (command, args) = original(&command, &args)?;
    let mut out = entry.clone();
    out["command"] = Value::String(command);
    out["args"] = Value::from(args);
    Some(out)
}

/// The user-level files of `hosts` and the servers they define.
pub fn user_servers(home: &Home, hosts: &[openmoat_hosts::Host]) -> Result<Vec<(Source, Server)>> {
    let mut out = Vec::new();
    for host in hosts {
        for source in servers::sources(home, *host, None)?
            .into_iter()
            .filter(|s| s.user)
        {
            let scan = servers::scan(std::slice::from_ref(&source));
            if let Some((path, why)) = scan.unreadable.first() {
                bail!("cannot read {}: {why}", path.display());
            }
            out.extend(scan.servers.into_iter().map(|s| (source.clone(), s)));
        }
    }
    Ok(out)
}

/// Write `edits` (server, new entry) into their files, backing each up first
/// unless `dry_run`.
pub fn write(home: &Home, edits: &[(Source, Done)], dry_run: bool) -> Result<()> {
    let mut by_file: BTreeMap<PathBuf, (Layout, Vec<&Done>)> = BTreeMap::new();
    for (source, done) in edits {
        by_file
            .entry(source.path.clone())
            .or_insert_with(|| (source.layout, Vec::new()))
            .1
            .push(done);
    }
    for (path, (layout, dones)) in by_file {
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let new = match layout {
            Layout::Json | Layout::ClaudeJson | Layout::JsonOrBare => edit_json(&text, &dones)?,
            Layout::Toml => edit_toml(&text, &dones)?,
            Layout::OpenClaw => {
                // JSON5 is written back as JSON, so a file with comments is not.
                let parsed = crate::install::openclaw::parse(&text)
                    .with_context(|| format!("parsing {}", path.display()))?;
                crate::install::openclaw::refuse_comments(&parsed, &path)?;
                edit_value(parsed.value, &dones)?
            }
        };
        if dry_run {
            continue;
        }
        crate::install::back_up(home, &path, MCP_BACKUP)?;
        write_private(&path, new.as_bytes())?;
    }
    Ok(())
}

fn edit_json(text: &str, dones: &[&Done]) -> Result<String> {
    edit_value(serde_json::from_str(text).context("parsing JSON")?, dones)
}

fn edit_value(mut root: Value, dones: &[&Done]) -> Result<String> {
    for done in dones {
        let slot = root
            .pointer_mut(&done.server.pointer)
            .with_context(|| format!("no server at {}", done.server.pointer))?;
        *slot = done.entry.clone();
    }
    Ok(serde_json::to_string_pretty(&root)? + "\n")
}

fn edit_toml(text: &str, dones: &[&Done]) -> Result<String> {
    let mut doc: DocumentMut = text.parse().context("parsing TOML")?;
    for done in dones {
        let table = doc
            .get_mut("mcp_servers")
            .and_then(|t| t.get_mut(&done.server.name))
            .with_context(|| format!("no [mcp_servers.{}]", done.server.name))?;
        let command = done.entry["command"].as_str().unwrap_or_default();
        let args: Array = done.entry["args"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        table["command"] = value(command);
        table["args"] = value(args);
    }
    Ok(doc.to_string())
}

/// Record `done` as wrapped (`true`) or no longer wrapped in `hosts.json`.
pub fn record(home: &Home, done: &[Done], wrapped: bool) -> Result<()> {
    let mut recorded = Recorded::load(home)?;
    for d in done {
        let entry = Wrapped {
            host: d.server.host.id().to_owned(),
            file: d.server.file.clone(),
            pointer: d.server.pointer.clone(),
            name: d.server.name.clone(),
        };
        recorded.mcp_wrapped.retain(|w| *w != entry);
        if wrapped {
            recorded.mcp_wrapped.push(entry);
        }
    }
    recorded.save(home)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn wrapping_keeps_the_original_after_the_separator_and_unwrapping_restores_it() {
        let entry = json!({"command": "npx", "args": ["-y", "--", "pkg"], "env": {"A": "1"}});
        let wrapped = wrapped(&entry, Path::new("/usr/local/bin/moat"), "gh", false).unwrap();
        assert_eq!(
            wrapped,
            json!({"command": "/usr/local/bin/moat",
                "args": ["mcp", "proxy", "--server", "gh", "--", "npx", "-y", "--", "pkg"],
                "env": {"A": "1"}})
        );
        assert_eq!(unwrapped(&wrapped).unwrap(), entry);
        assert!(super::wrapped(&wrapped, Path::new("/x/moat"), "gh", false).is_none());
        // Wrapped by `openmoat`, or by `moat` before the rename: both unwrap.
        let renamed =
            super::wrapped(&entry, Path::new("/usr/local/bin/openmoat"), "gh", false).unwrap();
        assert_eq!(unwrapped(&renamed).unwrap(), entry);
        assert!(super::wrapped(&renamed, Path::new("/x/openmoat"), "gh", false).is_none());
        let windows = json!({"command": "C:/scoop/apps/openmoat/current/openmoat.exe",
            "args": ["mcp", "proxy", "--server", "gh", "--", "npx"]});
        assert_eq!(
            unwrapped(&windows).unwrap(),
            json!({"command": "npx", "args": []})
        );
    }

    #[test]
    fn only_stdio_servers_are_wrapped() {
        let bin = Path::new("/b/moat");
        assert!(wrapped(&json!({"url": "https://x"}), bin, "a", false).is_none());
        assert!(wrapped(&json!({"type": "http", "command": "x"}), bin, "a", false).is_none());
        assert!(wrapped(&json!({"command": "x", "args": [1]}), bin, "a", false).is_none());
        let sandboxed = wrapped(&json!({"type": "stdio", "command": "x"}), bin, "a", true).unwrap();
        assert_eq!(sandboxed["args"][4], "--sandbox");
        // GitHub Copilot CLI calls a stdio server `local`.
        let local = json!({"type": "local", "command": "x", "tools": ["*"]});
        let wrapped_local = wrapped(&local, bin, "a", false).unwrap();
        assert_eq!(wrapped_local["type"], "local");
        assert_eq!(
            unwrapped(&wrapped_local).unwrap(),
            json!({"type": "local", "command": "x", "args": [], "tools": ["*"]})
        );
        assert!(
            unwrapped(&json!({"command": "npx", "args": ["mcp", "proxy", "--", "x"]})).is_none()
        );
    }

    #[test]
    fn toml_edits_keep_the_rest_of_the_file() {
        let text = "# mine\nmodel = \"x\"\n\n[mcp_servers.docs]\ncommand = \"docs\"\nenv = { A = \"1\" }\n";
        let server = Server {
            id: String::new(),
            host: openmoat_hosts::Host::Codex,
            file: PathBuf::from("/c/config.toml"),
            pointer: "/mcp_servers/docs".to_owned(),
            name: "docs".to_owned(),
            entry: json!({}),
        };
        let done = Done {
            entry: wrapped(
                &json!({"command": "docs"}),
                Path::new("/b/moat"),
                "docs",
                false,
            )
            .unwrap(),
            server,
        };
        let out = edit_toml(text, &[&done]).unwrap();
        assert!(out.starts_with("# mine\nmodel = \"x\""), "{out}");
        assert!(out.contains("command = \"/b/moat\""), "{out}");
        assert!(
            out.contains(r#"args = ["mcp", "proxy", "--server", "docs", "--", "docs"]"#),
            "{out}"
        );
        assert!(out.contains("env = { A = \"1\" }"), "{out}");
    }
}

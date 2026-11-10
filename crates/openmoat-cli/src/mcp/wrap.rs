//! `moat mcp wrap` and `unwrap`: point a stdio server's definition at
//! `moat mcp proxy`, and back.
//!
//! Wrapping replaces the program and its arguments and nothing else:
//! `{"command": "npx", "args": ["-y", "pkg"]}` becomes
//! `{"command": "<moat>", "args": ["mcp", "proxy", "--server", "<name>", "--host", "<agent>", "--", "npx", "-y", "pkg"]}`,
//! where `<agent>` is the agent whose file it is: the proxy takes only that
//! agent's hook decisions for its calls. Each host's reader names its form
//! (`form.rs`): OpenCode's one `command` list, goose's `cmd` and `args`.
//! The original stays in the arguments after `--`, so unwrapping needs no other
//! record, and `env`, `cwd` and the rest stay as they were. Only user-level files
//! are changed (`~/.claude.json`, Cursor's `mcp.json`, Codex's `config.toml`,
//! OpenClaw's `openclaw.json`, Copilot's `mcp-config.json`, pi's `mcp.json`,
//! Gemini CLI's `settings.json`, OpenCode's `config.json`, `opencode.json` and
//! `opencode.jsonc`): a project's `.mcp.json` is shared through its repository,
//! where the path of this machine's `moat` means nothing. A YAML file (Hermes
//! Agent's and goose's `config.yaml`) is not rewritten: what to set by hand is
//! named. Each file is backed up before its first change, and `hosts.json`
//! records every wrapped definition for `moat uninstall`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::{Host, McpCommandForm, McpSyntax};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use toml_edit::{Array, DocumentMut, value};

use super::servers::{self, Server, Source};
use crate::home::{Home, write_private};
use crate::install::Recorded;

mod form;
mod preview;

pub use form::not_wrappable;
pub use preview::preview;

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

/// `entry` running through the proxy at `binary`, in the common form of a
/// `command` and `args`; `None` when it is not a stdio server or is wrapped
/// already.
#[cfg(test)]
pub fn wrapped(entry: &Value, binary: &Path, name: &str, sandbox: bool) -> Option<Value> {
    wrapped_as(entry, binary, name, sandbox, McpCommandForm::CommandArgs)
}

/// `entry` in `form`, its host's reader's form, running through the proxy at
/// `binary`; `None` when it is not a local server in that form or is wrapped
/// already.
pub fn wrapped_as(
    entry: &Value,
    binary: &Path,
    name: &str,
    sandbox: bool,
    form: McpCommandForm,
) -> Option<Value> {
    let (command, args) = form::parts(entry, form)?;
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
    Some(form::written(
        entry,
        form,
        binary.display().to_string(),
        proxy,
    ))
}

/// The arguments `entry`, a definition in `form`, gives `moat mcp proxy`
/// (`mcp`, `proxy`, its flags, `--` and the server's command); `None` when it
/// is not wrapped. Every question about a definition below reads it in the
/// form its host's reader names, never guessed from its keys.
pub fn proxy_args(entry: &Value, form: McpCommandForm) -> Option<Vec<String>> {
    let (command, args) = form::parts(entry, form)?;
    original(&command, &args)?;
    Some(args)
}

/// Wrapped `entry` given the arguments `args` for the proxy.
fn with_proxy_args(entry: &Value, form: McpCommandForm, args: Vec<String>) -> Option<Value> {
    let (command, _) = form::parts(entry, form)?;
    Some(form::written(entry, form, command, args))
}

/// Whether wrapped `entry` starts its server in `moat run`'s sandbox; `None`
/// when it is not wrapped.
pub fn sandboxed(entry: &Value, form: McpCommandForm) -> Option<bool> {
    let args = proxy_args(entry, form)?;
    let split = args.iter().position(|a| a == "--")?;
    Some(args[..split].iter().any(|a| a == "--sandbox"))
}

/// Wrapped `entry` with its sandbox switched to `on`; `None` when it is not
/// wrapped or already so. Turning it off drops `--write`, which only the
/// sandbox reads.
pub fn with_sandbox(entry: &Value, form: McpCommandForm, on: bool) -> Option<Value> {
    if sandboxed(entry, form)? == on {
        return None;
    }
    let args = proxy_args(entry, form)?;
    let split = args.iter().position(|a| a == "--")?;
    let (flags, rest) = args.split_at(split);
    let mut kept: Vec<String> = Vec::new();
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--sandbox" => {}
            "--write" if !on => {
                flags.next();
            }
            f if !on && f.starts_with("--write=") => {}
            _ => kept.push(flag.clone()),
        }
    }
    if on {
        kept.push("--sandbox".to_owned());
    }
    kept.extend(rest.iter().cloned());
    with_proxy_args(entry, form, kept)
}

/// Wrapped `entry` with `--host <host>`, so the proxy takes only `host`'s hook
/// decisions; `None` when it is not wrapped or names its host already. A
/// definition wrapped before the proxy took `--host` is given it the next
/// time it is wrapped.
pub fn with_host(entry: &Value, form: McpCommandForm, host: Host) -> Option<Value> {
    let args = proxy_args(entry, form)?;
    let split = args.iter().position(|a| a == "--")?;
    let flags = &args[..split];
    if flags
        .iter()
        .any(|a| a == "--host" || a.starts_with("--host="))
    {
        return None;
    }
    let mut kept = flags.to_vec();
    kept.extend(["--host".to_owned(), host.id().to_owned()]);
    kept.extend(args[split..].iter().cloned());
    with_proxy_args(entry, form, kept)
}

/// Whether `entry` starts a local process: a `command` (a string, or a list
/// as OpenCode writes it) or goose's `cmd`, and no remote `type`; or goose's
/// inline Python, which it runs itself. Such a server runs its command when
/// the host starts, before any tool call reaches a hook.
pub fn starts_process(entry: &Value) -> bool {
    let kind = entry.get("type").and_then(Value::as_str);
    if kind == Some("inline_python") {
        return true;
    }
    let local = kind.is_none_or(|t| matches!(t, "stdio" | "local"));
    let names = |key: &str| match entry.get(key) {
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        _ => false,
    };
    local && (names("command") || names("cmd"))
}

/// `entry` as it was before wrapping; `None` when it is not wrapped.
pub fn unwrapped(entry: &Value, form: McpCommandForm) -> Option<Value> {
    let (command, args) = form::parts(entry, form)?;
    let (command, args) = original(&command, &args)?;
    Some(form::written(entry, form, command, args))
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
    let mut by_file: BTreeMap<PathBuf, (McpSyntax, Vec<&Done>)> = BTreeMap::new();
    for (source, done) in edits {
        by_file
            .entry(source.path.clone())
            .or_insert_with(|| (source.reader.syntax(), Vec::new()))
            .1
            .push(done);
    }
    for (path, (syntax, dones)) in by_file {
        let (_, new) = rendered(&path, syntax, &dones)?;
        if dry_run {
            continue;
        }
        crate::install::back_up(home, &path, MCP_BACKUP)?;
        write_private(&path, new.as_bytes())?;
    }
    Ok(())
}

/// The text of the file at `path` and what `dones` would make it; `Err` when
/// OpenMoat does not rewrite such a file, with what to set by hand.
fn rendered(path: &Path, syntax: McpSyntax, dones: &[&Done]) -> Result<(String, String)> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let new = match syntax {
        McpSyntax::Json => edit_json(&text, dones)?,
        McpSyntax::Toml => edit_toml(&text, dones)?,
        McpSyntax::Json5 => {
            // JSON5 is written back as JSON, so a file with comments is not.
            let parsed = crate::install::json5_file::parse_or_empty(&text)
                .with_context(|| format!("parsing {}", path.display()))?;
            crate::install::json5_file::refuse_comments(&parsed, path)?;
            edit_value(parsed.value, dones)?
        }
        // The host rewrites it and people keep comments in it; OpenMoat
        // edits only its own hook lines there.
        McpSyntax::Yaml => bail!(
            "{} is YAML, which `openmoat mcp {}` does not rewrite; set these by hand, \
             then run `openmoat mcp accept`:\n{}",
            path.display(),
            if dones
                .iter()
                .any(|d| original_of(&d.entry, d.server.form).is_some())
            {
                "wrap"
            } else {
                "unwrap"
            },
            by_hand(dones)
        ),
    };
    Ok((text, new))
}

/// Whether `entry` (a definition as it is to be written) runs through the
/// proxy: what it ran before, when it does.
fn original_of(entry: &Value, form: McpCommandForm) -> Option<(String, Vec<String>)> {
    let (command, args) = form::parts(entry, form)?;
    original(&command, &args)
}

/// Each server's program and `args` as they are to be written, one line each.
fn by_hand(dones: &[&Done]) -> String {
    dones
        .iter()
        .map(|done| {
            let key = form::program_key(done.server.form);
            format!(
                "  {}: {key}: {}, args: {}",
                done.server.name,
                done.entry[key],
                done.entry.get("args").unwrap_or(&Value::Null)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
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

    // These read a definition in the common form of a `command` and `args`.
    const FORM: McpCommandForm = McpCommandForm::CommandArgs;

    fn unwrapped(entry: &Value) -> Option<Value> {
        super::unwrapped(entry, FORM)
    }

    fn sandboxed(entry: &Value) -> Option<bool> {
        super::sandboxed(entry, FORM)
    }

    fn with_sandbox(entry: &Value, on: bool) -> Option<Value> {
        super::with_sandbox(entry, FORM, on)
    }

    fn with_host(entry: &Value, host: Host) -> Option<Value> {
        super::with_host(entry, FORM, host)
    }

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
    fn the_sandbox_choice_is_read_and_switched_in_place() {
        let bin = Path::new("/b/openmoat");
        let plain = json!({"command": "npx", "args": ["pkg", "--sandbox"], "env": {"A": "1"}});
        assert_eq!(sandboxed(&plain), None, "not wrapped");
        let off = wrapped(&plain, bin, "gh", false).unwrap();
        assert_eq!(
            sandboxed(&off),
            Some(false),
            "a `--sandbox` after `--` is the server's"
        );
        assert!(with_sandbox(&off, false).is_none(), "already off");
        let on = with_sandbox(&off, true).unwrap();
        assert_eq!(
            on["args"],
            json!([
                "mcp",
                "proxy",
                "--server",
                "gh",
                "--sandbox",
                "--",
                "npx",
                "pkg",
                "--sandbox"
            ])
        );
        assert_eq!(on["env"], json!({"A": "1"}));
        assert_eq!(on, wrapped(&plain, bin, "gh", true).unwrap());
        let mut writes = on.clone();
        writes["args"] = json!([
            "mcp",
            "proxy",
            "--server",
            "gh",
            "--sandbox",
            "--write",
            "/w",
            "--write=/v",
            "--",
            "npx"
        ]);
        assert_eq!(
            with_sandbox(&writes, false).unwrap()["args"],
            json!(["mcp", "proxy", "--server", "gh", "--", "npx"])
        );
        assert_eq!(unwrapped(&on).unwrap(), unwrapped(&off).unwrap());
    }

    #[test]
    fn the_host_is_added_once_before_the_separator() {
        let [first, second, ..] = Host::ALL;
        let plain = json!({"command": "npx", "args": ["pkg", "--host", "x"]});
        assert!(with_host(&plain, first).is_none(), "not wrapped");
        let off = wrapped(&plain, Path::new("/b/openmoat"), "gh", true).unwrap();
        let named = with_host(&off, second).unwrap();
        assert_eq!(
            named["args"],
            json!([
                "mcp",
                "proxy",
                "--server",
                "gh",
                "--sandbox",
                "--host",
                second.id(),
                "--",
                "npx",
                "pkg",
                "--host",
                "x"
            ])
        );
        assert!(with_host(&named, first).is_none(), "named once");
        assert_eq!(unwrapped(&named).unwrap(), unwrapped(&off).unwrap());
    }

    #[test]
    fn a_local_command_starts_a_process_and_a_url_does_not() {
        assert!(starts_process(&json!({"command": "npx"})));
        assert!(starts_process(
            &json!({"type": "local", "command": ["npx", "x"]})
        ));
        assert!(!starts_process(&json!({"url": "https://x"})));
        assert!(!starts_process(&json!({"type": "http", "command": "x"})));
        assert!(!starts_process(&json!({"command": ""})));
    }

    #[test]
    fn toml_edits_keep_the_rest_of_the_file() {
        let text = "# mine\nmodel = \"x\"\n\n[mcp_servers.docs]\ncommand = \"docs\"\nenv = { A = \"1\" }\n";
        let server = Server {
            id: String::new(),
            host: Host::EVERY[0],
            file: PathBuf::from("/c/config.toml"),
            pointer: "/mcp_servers/docs".to_owned(),
            name: "docs".to_owned(),
            entry: json!({}),
            form: FORM,
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

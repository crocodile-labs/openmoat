//! A tool an adapter does not map: one rule for every host.
//!
//! Hosts add tools all the time (a pi or OpenClaw extension's, a Gemini CLI
//! subagent's, a Copilot CLI release's), and some hosts run a call the hook
//! makes no decision on. So such a tool is never judged by its name alone:
//! every path and URL its arguments name, by key as for MCP tools
//! ([`super::mcp`]) and by look anywhere else, is checked, and every string
//! under a key that names a shell command (`command`, `cmd`, `script`) is
//! classified as one. The call is then `tool.unknown` together with all of
//! that, so what it names decides it too. Arguments that cannot all be read
//! (nested too deep, too many) are an error, so the guard denies.

use openmoat_core::Action;
use serde_json::Value;

use super::mcp::{MAX_DEPTH, MAX_RESOURCES, Resources, arguments, strings};
use crate::{Host, HostError};

/// Keys (in snake case) whose value is a shell command line.
const COMMAND_KEYS: &[&str] = &[
    "command",
    "commands",
    "cmd",
    "script",
    "shell",
    "shell_command",
    "command_line",
    "cmdline",
];

/// URL schemes a string is read as a host to contact by.
const URL_SCHEMES: &[&str] = &["http://", "https://", "ws://", "wss://", "ftp://"];

/// Longest string read as a path by its look; longer ones are text.
const MAX_PATH_LEN: usize = 4096;

/// The action of `host`'s `tool`, which its adapter does not map, with
/// arguments `input` (a JSON string is parsed).
pub(crate) fn action(host: Host, tool: &str, input: &Value) -> Result<Action, HostError> {
    let found = walk(tool, input)?;
    Ok(Action::UnknownTool {
        host: host.id().to_owned(),
        tool: tool.to_owned(),
        reads: found.reads,
        writes: found.writes,
        hosts: found.hosts,
        commands: found.commands,
    })
}

/// The action of a tool that may be an MCP server's or one of the host's own,
/// for a host whose payload does not tell them apart: decided as the MCP tool
/// `name` (so its server's pins apply) with its arguments read as for an
/// unknown tool.
pub(crate) fn mcp(name: &str, input: &Value) -> Result<Action, HostError> {
    let found = walk(name, input)?;
    Ok(Action::McpTool {
        name: name.to_owned(),
        reads: found.reads,
        writes: found.writes,
        hosts: found.hosts,
        commands: found.commands,
        unchecked: None,
    })
}

fn walk(tool: &str, input: &Value) -> Result<Resources, HostError> {
    let args = arguments(tool, input)?;
    let lower = tool.to_ascii_lowercase();
    let mut found = Resources {
        writes_by_default: crate::WRITE_VERBS.iter().any(|verb| lower.contains(verb)),
        everything: true,
        ..Resources::default()
    };
    found.walk(&args, 0);
    let problem = if found.count() > MAX_RESOURCES {
        Some(format!(
            "more than {MAX_RESOURCES} paths, URLs and commands"
        ))
    } else {
        found
            .unchecked
            .take()
            .map(|_| format!("arguments nested deeper than {MAX_DEPTH} levels"))
    };
    if let Some(problem) = problem {
        return Err(HostError::MalformedArguments {
            tool: tool.to_owned(),
            problem,
        });
    }
    for list in [
        &mut found.reads,
        &mut found.writes,
        &mut found.hosts,
        &mut found.commands,
    ] {
        dedup(list);
    }
    Ok(found)
}

/// `list` with each value once, in the order first seen: a path under a path
/// key is also a path by its look.
fn dedup(list: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    list.retain(|item| seen.insert(item.clone()));
}

/// The command lines a command key holds: a list of words is one line (an
/// argv), each word quoted; any other value, every string in it.
pub(super) fn command_lines(value: &Value) -> Vec<String> {
    match value {
        Value::Array(words) if !words.is_empty() && words.iter().all(Value::is_string) => {
            let quoted: Vec<String> = words
                .iter()
                .filter_map(Value::as_str)
                .map(|word| format!("'{}'", word.replace('\'', r"'\''")))
                .collect();
            vec![quoted.join(" ")]
        }
        other => strings(other),
    }
}

/// Whether the snake-case `key` names a shell command line.
pub(super) fn names_a_command(key: &str) -> bool {
    COMMAND_KEYS.contains(&key)
        || ["_command", "_cmd", "_script"]
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

/// What a string is by its look.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Looks {
    /// A path from the root, a drive or the home directory (a `file:` URL as
    /// the path it names).
    Path(String),
    /// A URL with a scheme that connects somewhere.
    Url,
}

/// `text` as a path or a URL when it is one by its look: one line, starting
/// at a root (`/`, `\`, `C:\`, `C:/`), at `~` or with a `file:` or network
/// URL scheme. A relative word is text: only a key can say it is a path.
pub(super) fn looks_like(text: &str) -> Option<Looks> {
    if text.is_empty() || text.len() > MAX_PATH_LEN || text.contains(['\n', '\r']) {
        return None;
    }
    let lower = text.get(..8).unwrap_or(text).to_ascii_lowercase();
    if URL_SCHEMES.iter().any(|scheme| lower.starts_with(scheme)) {
        return (!text.contains(char::is_whitespace)).then_some(Looks::Url);
    }
    if lower.starts_with("file:") {
        return openmoat_core::file_url_path(text).map(Looks::Path);
    }
    let bytes = text.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    let rooted = text.starts_with(['/', '\\']) || text == "~" || text.starts_with("~/");
    (drive || rooted).then(|| Looks::Path(text.to_owned()))
}

#[cfg(test)]
mod tests;

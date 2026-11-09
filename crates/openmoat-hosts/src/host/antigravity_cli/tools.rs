//! Which action an Antigravity CLI tool call is, from its name and arguments
//! (the tool list and argument names of <https://antigravity.google/docs/hooks?tab=cli>).
//!
//! A tool not named here is unknown, never allowed silently: what its
//! arguments name is checked and `tool.unknown` decides the tool itself.

use openmoat_core::Action;
use serde_json::{Map, Value};

use crate::{Host, HostError};

/// What one call is, and what the request records besides its action.
pub(super) struct Mapped {
    /// The action, or `None` for a tool OpenMoat does not govern.
    pub action: Option<Action>,
    /// The name to record when it is not Antigravity CLI's own.
    pub tool: Option<String>,
}

impl Mapped {
    fn action(action: Action) -> Self {
        Self {
            action: Some(action),
            tool: None,
        }
    }

    fn none() -> Self {
        Self {
            action: None,
            tool: None,
        }
    }
}

/// Tools that only talk to the person or read Antigravity CLI's own state.
const UNGOVERNED: &[&str] = &["ask_question", "list_permissions", "ask_permission"];

/// `true` on Windows, where the documentation does not say which shell runs
/// `run_command`; the guard runs on the same machine.
pub(super) const WINDOWS: bool = cfg!(windows);

pub(super) fn map(tool: &str, input: &Value, cwd: Option<&str>) -> Result<Mapped, HostError> {
    map_on(tool, input, cwd, WINDOWS)
}

pub(super) fn map_on(
    tool: &str,
    input: &Value,
    cwd: Option<&str>,
    windows: bool,
) -> Result<Mapped, HostError> {
    let field = |name: &'static str| crate::input_str(input, tool, name);
    let action = match tool {
        "run_command" => command(input, field("CommandLine")?, windows),
        "view_file" => Action::FsRead {
            path: field("AbsolutePath")?,
        },
        "write_to_file" | "replace_file_content" | "multi_replace_file_content" => {
            Action::FsWrite {
                path: field("TargetFile")?,
            }
        }
        "list_dir" => Action::FsRead {
            path: field("DirectoryPath")?,
        },
        "find_by_name" => {
            let root = rooted(field("SearchDirectory")?, cwd);
            let pattern = input
                .get("Pattern")
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty());
            search(root, pattern.into_iter().collect())
        }
        "grep_search" => {
            let root = rooted(field("SearchPath")?, cwd);
            search(root, includes(input))
        }
        "search_web" => Action::WebSearch {
            query: field("query")?,
        },
        "read_url_content" => Action::Fetch { url: field("Url")? },
        "manage_task" => return manage_task(tool, input),
        "manage_subagents" => return manage_subagents(tool, input),
        "schedule" => held(
            tool,
            input,
            "`schedule` runs a prompt later, unattended, which OpenMoat cannot check now",
        )?,
        "define_subagent" => held(
            tool,
            input,
            "`define_subagent` writes a system prompt and tool grants for a later agent",
        )?,
        "invoke_subagent" => held(
            tool,
            input,
            "`invoke_subagent` starts an agent whose calls may not reach OpenMoat's hook: \
             Antigravity CLI does not document that they do",
        )?,
        "call_mcp_tool" => return call_mcp_tool(tool, input),
        "generate_image" => generate_image(tool, input)?,
        name if UNGOVERNED.contains(&name) => return Ok(Mapped::none()),
        // `mcp_<server>_<tool>` cannot be split back into its parts: decided
        // as an MCP tool of that name, with its arguments read as for an
        // unknown tool, so a server's pins still hold it back.
        name if name.starts_with("mcp_") => crate::wire::unknown::mcp(name, input)?,
        // `send_message` and any tool the docs do not list.
        _ => crate::wire::unknown::action(Host::AntigravityCli, tool, input)?,
    };
    Ok(Mapped::action(action))
}

/// A command as it runs: after a `cd` to `Cwd`, when given, so a relative path
/// in it resolves where it runs; marked unchecked when it runs in a terminal
/// an earlier call left, whose directory and environment the call does not
/// show.
fn command(input: &Value, command: String, windows: bool) -> Action {
    if windows {
        return Action::ForeignShell {
            shell: "the Windows shell".to_owned(),
            command,
        };
    }
    let command = match input.get("Cwd").and_then(Value::as_str).filter(|c| !c.is_empty()) {
        Some(dir) => format!("cd '{}' && {command}", dir.replace('\'', r"'\''")),
        None => command,
    };
    let shell = Action::Shell { command };
    let terminal = input
        .get("RequestedTerminalID")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty());
    if terminal {
        Action::unchecked(
            shell,
            "the command runs in a terminal an earlier call left, whose directory and \
             environment this call does not show",
        )
    } else {
        shell
    }
}

/// `dir`, made absolute against the working directory.
fn rooted(dir: String, cwd: Option<&str>) -> String {
    let bytes = dir.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if drive || dir.starts_with(['/', '\\', '~']) {
        return dir;
    }
    cwd.map_or(dir.clone(), |cwd| crate::below(cwd, &dir))
}

/// `Includes`, a list or one pattern; the documentation gives no type.
fn includes(input: &Value) -> Vec<&str> {
    match input.get("Includes") {
        Some(Value::String(one)) if !one.is_empty() => vec![one],
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(Value::as_str)
            .filter(|p| !p.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// A search of `root` for `patterns`: the root, the directory each pattern
/// names before its first wildcard (an absolute one outright), and where a
/// `..` climbs to.
fn search(root: String, patterns: Vec<&str>) -> Action {
    let mut paths = vec![root.clone()];
    for pattern in &patterns {
        if let Some(wild) = pattern.find(['*', '?', '[', '{']) {
            if let Some(end) = pattern[..wild].rfind(['/', '\\']) {
                paths.push(if crate::pattern_dir(pattern).is_some() {
                    pattern[..end.max(1)].to_owned()
                } else {
                    crate::below(&root, &pattern[..end])
                });
            }
        } else if let Some(dir) = crate::pattern_dir(pattern) {
            paths.push(dir);
        } else {
            paths.push(crate::below(&root, pattern));
        }
        paths.extend(crate::glob_reach(&root, pattern));
    }
    paths.dedup();
    let action = match paths.len() {
        1 => Action::FsRead { path: root },
        _ => Action::ReadFiles { paths },
    };
    crate::bounded(action, patterns)
}

/// The call as an unknown tool, read for what it names, and held for review.
fn held(tool: &str, input: &Value, reason: &'static str) -> Result<Action, HostError> {
    let action = crate::wire::unknown::action(Host::AntigravityCli, tool, input)?;
    Ok(Action::unchecked(action, reason))
}

/// `manage_task` with `send_input` types `Input` into a running shell, which
/// joins it to what came before: the typed text is checked on its own and the
/// call needs review at least. The others only read or end tasks the agent
/// started.
fn manage_task(tool: &str, input: &Value) -> Result<Mapped, HostError> {
    match crate::input_str(input, tool, "Action")?.as_str() {
        "send_input" => {
            let command = crate::input_str(input, tool, "Input")?;
            Ok(Mapped::action(Action::unchecked(
                Action::Shell { command },
                "input typed into a running shell joins what was typed before, which this call \
                 does not show",
            )))
        }
        "list" | "status" | "kill" => Ok(Mapped::none()),
        _ => Ok(Mapped::action(crate::wire::unknown::action(
            Host::AntigravityCli,
            tool,
            input,
        )?)),
    }
}

/// `manage_subagents` lists or ends subagents; an action the docs do not list
/// is unknown.
fn manage_subagents(tool: &str, input: &Value) -> Result<Mapped, HostError> {
    match crate::input_str(input, tool, "Action")?.as_str() {
        "list" | "kill" | "kill_all" => Ok(Mapped::none()),
        _ => Ok(Mapped::action(crate::wire::unknown::action(
            Host::AntigravityCli,
            tool,
            input,
        )?)),
    }
}

/// The lazy way to call an MCP tool: `ServerName`, `ToolName` and `Arguments`
/// name it outright, so it is recorded as `mcp__<server>__<tool>`.
fn call_mcp_tool(tool: &str, input: &Value) -> Result<Mapped, HostError> {
    let server = crate::input_str(input, tool, "ServerName")?;
    let name = crate::input_str(input, tool, "ToolName")?;
    let recorded = format!("mcp__{server}__{name}");
    let empty = Value::Object(Map::new());
    let arguments = input.get("Arguments").unwrap_or(&empty);
    let action = crate::wire::mcp::action(&recorded, arguments)?;
    Ok(Mapped {
        action: Some(action),
        tool: Some(recorded),
    })
}

/// `ImagePaths` are read and sent to the model; with none the tool only makes
/// an image, a tool OpenMoat has no other rule for.
fn generate_image(tool: &str, input: &Value) -> Result<Action, HostError> {
    let paths: Vec<String> = input
        .get("ImagePaths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    if paths.is_empty() {
        crate::wire::unknown::action(Host::AntigravityCli, tool, input)
    } else {
        Ok(Action::ReadFiles { paths })
    }
}

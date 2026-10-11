//! Cursor `preToolUse`: which action a tool call is, from its name and the
//! paths its input names.

use openmoat_core::Action;
use serde_json::Value;

use crate::{Host, HostError};

/// Keys that name a file or directory in a Cursor tool's input. `path` and
/// `file_path` are seen in Cursor payloads; the `target_*` keys are the names
/// Cursor's own search and list tools use, read so such a tool is never
/// passed unchecked.
const PATH_KEYS: &[&str] = &[
    "path",
    "file_path",
    "target_file",
    "target_directory",
    "target_directories",
];

/// Shell commands are governed by `beforeShellExecution` and MCP tools by
/// `beforeMCPExecution`, so `Shell` and `MCP:<tool>` here are deliberately
/// ungoverned to avoid deciding and auditing the same call twice. `Task` runs a
/// subagent whose own tool calls are hooked. `WebSearch` and `WebFetch` are a
/// web search and a fetch, as in Claude Code.
///
/// Cursor documents tool names but no file tool's arguments
/// (`tests/fixtures/hosts/cursor/README.md`, #138). A search reads every path
/// key it carries (a captured `Grep` sends `file_path`, not `path`). Any other
/// tool that names a path is checked instead of passed: as writing it when its
/// name is write-shaped (`DeleteDirectory`, `Rename`), else as reading it. A
/// tool that names no such path is an [`Action::UnknownTool`], which the policy
/// decides (`ask` by default) instead of passing it unseen.
pub(super) fn pre_tool_action(
    tool: &str,
    input: &Value,
    cwd: Option<&str>,
) -> Result<Option<Action>, HostError> {
    let field = |name: &'static str| crate::input_str(input, tool, name);
    Ok(match tool {
        "Shell" | "Task" => None,
        name if name.starts_with("MCP:") => None,
        "Write" | "Edit" | "MultiEdit" | "StrReplace" | "Delete" => Some(Action::FsWrite {
            path: field("file_path")?,
        }),
        "Read" => Some(Action::FsRead {
            path: field("file_path")?,
        }),
        // Cursor keeps Claude Code's `WebSearch` name; its `query` key is assumed.
        "WebSearch" => Some(Action::WebSearch {
            query: field("query")?,
        }),
        // Cursor keeps Claude Code's `WebFetch` name; its `url` key is assumed.
        "WebFetch" => Some(Action::Fetch { url: field("url")? }),
        "Grep" | "Glob" => {
            Some(reads(read_paths(tool, input)?).unwrap_or_else(|| crate::search_root(input, cwd)))
        }
        _ => {
            let paths = read_paths(tool, input)?;
            let checked = if is_write_shaped(tool) {
                writes(paths)
            } else {
                reads(paths)
            };
            match checked {
                None if AGENT_STATE_TOOLS.contains(&tool) => None,
                checked => Some(checked.unwrap_or_else(|| unknown(tool))),
            }
        }
    })
}

/// Tools that change only the agent's own to-do list, so they stay ungoverned
/// when they name no path. Cursor documents none of them; the names are Claude
/// Code's, which Cursor keeps for third-party hooks, and the agent's own
/// `todo_write`.
const AGENT_STATE_TOOLS: &[&str] = &["TodoWrite", "TodoRead", "todo_write"];

fn unknown(tool: &str) -> Action {
    Action::UnknownTool {
        host: Host::Cursor.id().to_owned(),
        tool: tool.to_owned(),
    }
}

fn is_write_shaped(tool: &str) -> bool {
    let tool = tool.to_ascii_lowercase();
    crate::WRITE_VERBS.iter().any(|verb| tool.contains(verb))
}

/// Every non-empty path under [`PATH_KEYS`]. A path key holding anything but a
/// string or a list of strings cannot be checked, so it is an error.
fn read_paths(tool: &str, input: &Value) -> Result<Vec<String>, HostError> {
    let malformed = || HostError::MalformedArguments {
        tool: tool.to_owned(),
        problem: "a path argument is not a string or a list of strings".to_owned(),
    };
    let mut paths = Vec::new();
    for key in PATH_KEYS {
        match input.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(path)) => paths.push(path.clone()),
            Some(Value::Array(list)) => {
                for path in list {
                    paths.push(path.as_str().ok_or_else(malformed)?.to_owned());
                }
            }
            Some(_) => return Err(malformed()),
        }
    }
    paths.retain(|p| !p.is_empty());
    Ok(paths)
}

/// One path is an `FsRead`, several a `ReadFiles`, none no action.
fn reads(mut paths: Vec<String>) -> Option<Action> {
    match paths.len() {
        0 => None,
        1 => paths.pop().map(|path| Action::FsRead { path }),
        _ => Some(Action::ReadFiles { paths }),
    }
}

/// One path is an `FsWrite`; several a `Patch`, the action that writes many
/// files at once; none no action.
fn writes(mut paths: Vec<String>) -> Option<Action> {
    match paths.len() {
        0 => None,
        1 => paths.pop().map(|path| Action::FsWrite { path }),
        _ => Some(Action::Patch { writes: paths }),
    }
}

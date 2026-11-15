//! Which action a Qwen Code tool call is, from its name and arguments.
//!
//! Tool names: `ToolNames` in `packages/core/src/tools/tool-names.ts`; argument
//! keys: each tool's `*Params` in `packages/core/src/tools/` (`shell.ts`,
//! `read-file.ts`, `write-file.ts`, `edit.ts`, `glob.ts`, `grep.ts`, `ls.ts`,
//! `web-fetch.ts`), `QwenLM/qwen-code` `main`, read 2026-11-14.

use openmoat_core::Action;
use serde_json::Value;

use crate::{Host, HostError};

/// Tools that change only Qwen Code's own state or talk to the person; the
/// shared mapping records them as `ungoverned`.
pub(super) const UNGOVERNED: &[&str] = &[
    "todo_write",
    "ask_user_question",
    "enter_plan_mode",
    "exit_plan_mode",
    "tool_search",
];

/// Qwen Code runs `run_shell_command` with PowerShell on Windows, as the
/// Gemini CLI it was forked from does (not verified), and with bash
/// elsewhere; the guard runs on the same machine.
pub(super) const POWERSHELL: bool = cfg!(windows);

/// The action of a Qwen Code tool; `None` for an MCP tool (`mcp__…`) or an
/// ungoverned one, which the shared mapping reads.
pub(super) fn action(
    tool: &str,
    input: &Value,
    cwd: Option<&str>,
) -> Option<Result<Action, HostError>> {
    if tool.starts_with("mcp__") || UNGOVERNED.contains(&tool) {
        return None;
    }
    Some(map(tool, input, cwd, POWERSHELL))
}

pub(super) fn map(
    tool: &str,
    input: &Value,
    cwd: Option<&str>,
    powershell: bool,
) -> Result<Action, HostError> {
    let field = |name: &'static str| crate::input_str(input, tool, name);
    Ok(match tool {
        "" => {
            return Err(HostError::MissingField {
                tool: crate::wire::pre_tool_use::EVENT.to_owned(),
                field: "tool_name",
            });
        }
        "run_shell_command" if powershell => Action::ForeignShell {
            shell: "PowerShell".to_owned(),
            command: field("command")?,
        },
        "run_shell_command" => Action::Shell {
            command: in_dir(input, field("command")?),
        },
        "read_file" => Action::FsRead {
            path: field("file_path")?,
        },
        "write_file" | "edit" => Action::FsWrite {
            path: field("file_path")?,
        },
        "list_directory" => Action::FsRead {
            path: field("path")?,
        },
        // `pattern` and `path`, as Claude Code's `Glob` and `Grep` take them.
        "glob" => crate::glob_roots(input, cwd),
        "grep_search" => crate::search_root(input, cwd),
        "web_fetch" => Action::Fetch { url: field("url")? },
        // `query` is the key Claude Code's and Gemini CLI's search tools take;
        // Qwen Code's schema was not read, so a call without it is refused.
        "web_search" => Action::WebSearch {
            query: field("query")?,
        },
        "read_mcp_resource" => crate::wire::mcp::read_resource(tool, input)?,
        // Every other tool (`agent`, `skill`, `exec`, `notebook_edit`,
        // `save_memory`, `monitor`, `enter_worktree`, a discovered tool, …):
        // what it touches is not mapped, so what its arguments name is checked.
        _ => crate::wire::unknown::action(Host::QwenCode, tool, input)?,
    })
}

/// `command` as it runs in `directory`, when the call names one: after a `cd`
/// there, so its relative paths resolve where Qwen Code runs it while the
/// project stays the session's. The path is quoted whole.
fn in_dir(input: &Value, command: String) -> String {
    match input
        .get("directory")
        .and_then(Value::as_str)
        .filter(|d| !d.is_empty())
    {
        Some(dir) => format!("cd '{}' && {command}", dir.replace('\'', r"'\''")),
        None => command,
    }
}

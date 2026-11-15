//! Which action a Crush tool call is, from its name and arguments.
//!
//! Tool names: `allToolNames()` in `internal/config/config.go` and the
//! constants of `internal/agent/tools/*.go`; argument keys: each tool's
//! `*Params` JSON tags there (`charmbracelet/crush` `main`, read 2026-11-14).

use openmoat_core::Action;
use serde_json::Value;

use crate::{Host, HostError};

/// Tools that change only Crush's own state, talk to the person, or read
/// what Crush keeps itself (a background job's output, its own log); the
/// shared mapping records them as `ungoverned`.
pub(super) const UNGOVERNED: &[&str] = &[
    "todos",
    "question",
    "job_output",
    "job_kill",
    "crush_logs",
    "crush_info",
    "list_mcp_resources",
    "agent_status",
];

/// Crush runs `bash` in its embedded POSIX shell; on Windows that was not
/// checked, so a command there is left to Crush, never classified.
pub(super) const FOREIGN_SHELL: bool = cfg!(windows);

/// What a subagent's start needs review for: its own tool calls fire no
/// hook (the hooks page; `wrapToolsWithHooks` in `internal/agent`).
const SUBAGENT: &str = "the tool calls of a Crush subagent fire no hook, so OpenMoat cannot \
                        check what it does";

/// The action of a Crush tool; `None` for an ungoverned one, which the shared
/// mapping reads.
pub(super) fn action(
    tool: &str,
    input: &Value,
    cwd: Option<&str>,
) -> Option<Result<Action, HostError>> {
    if UNGOVERNED.contains(&tool) {
        return None;
    }
    Some(map(tool, input, cwd, FOREIGN_SHELL))
}

pub(super) fn map(
    tool: &str,
    input: &Value,
    cwd: Option<&str>,
    foreign_shell: bool,
) -> Result<Action, HostError> {
    let field = |name: &'static str| crate::input_str(input, tool, name);
    Ok(match tool {
        "" => {
            return Err(HostError::MissingField {
                tool: crate::wire::pre_tool_use::EVENT.to_owned(),
                field: "tool_name",
            });
        }
        "bash" if foreign_shell => Action::ForeignShell {
            shell: "Crush".to_owned(),
            command: field("command")?,
        },
        "bash" => Action::Shell {
            command: in_dir(input, field("command")?),
        },
        "view" | "lsp_diagnostics" | "lsp_symbols" => Action::FsRead {
            path: field("file_path")?,
        },
        "write" | "edit" | "multiedit" | "lsp_replace_symbol" => Action::FsWrite {
            path: field("file_path")?,
        },
        // `path`, else the working directory; `grep`'s `pattern` and `path` are
        // Claude Code's `Grep`'s.
        "ls" | "grep" => crate::search_root(input, cwd),
        // `pattern` and `path`, as Claude Code's `Glob` takes them.
        "glob" => crate::glob_roots(input, cwd),
        "fetch" | "web_fetch" => Action::Fetch { url: field("url")? },
        // `web_search` sends `query` to Crush's search provider; `sourcegraph`
        // sends it to sourcegraph.com.
        "web_search" | "sourcegraph" => Action::WebSearch {
            query: field("query")?,
        },
        "read_mcp_resource" => crate::wire::mcp::read_resource(tool, input)?,
        // A subagent: what it is asked to do is checked, and it needs review.
        "agent" | "agentic_fetch" => Action::unchecked(
            crate::wire::unknown::action(Host::Crush, tool, input)?,
            SUBAGENT,
        ),
        // An MCP server's tool, `mcp_<server>_<tool>`, which cannot be split back
        // into its parts: decided as the MCP tool of that name, by its prefix.
        name if name.starts_with("mcp_") => crate::wire::unknown::mcp(name, input)?,
        // Every other tool (`download`, which fetches `url` into `file_path`,
        // `lsp_rename`, `lsp_references`, `agent_dispatch`, a tool added later):
        // what its arguments name is checked.
        _ => crate::wire::unknown::action(Host::Crush, tool, input)?,
    })
}

/// `command` as it runs in `working_dir`, when the call names one: after a
/// `cd` there, so its relative paths resolve where Crush runs it while the
/// project stays the session's. The path is quoted whole.
fn in_dir(input: &Value, command: String) -> String {
    match input
        .get("working_dir")
        .and_then(Value::as_str)
        .filter(|d| !d.is_empty())
    {
        Some(dir) => format!("cd '{}' && {command}", dir.replace('\'', r"'\''")),
        None => command,
    }
}

//! `PreToolUse` hook format shared by Claude Code and Codex.
//!
//! Input: JSON on stdin with `tool_name`, `tool_input`, `session_id`, `cwd`.
//! Output: JSON on stdout with `hookSpecificOutput.permissionDecision`
//! (`allow` | `deny` | `ask`) and a reason the model gets to see.

use openmoat_core::{Action, Decision, Verdict};
use serde::Deserialize;
use serde_json::Value;

use crate::{HookEvent, HookRequest, Host, HostError};

pub(crate) const EVENT: &str = "PreToolUse";

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    tool_use_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
    /// Claude Code's permission mode for the session (`default`, `acceptEdits`,
    /// `plan`, `auto`, `dontAsk`, `bypassPermissions`).
    #[serde(default)]
    permission_mode: Option<String>,
}

/// Claude Code permission modes in which no question reaches a person:
/// `bypassPermissions` skips its prompts and `dontAsk` denies whatever would
/// prompt. An `ask` there is answered as a deny that says how to approve it.
const MODES_WITHOUT_PROMPT: &[&str] = &["bypassPermissions", "dontAsk"];

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    let action = map_tool(&p.tool_name, &p.tool_input, p.cwd.as_deref())?;
    // `Write` replaces the whole file with `content` (an empty file included).
    let content = match p.tool_name.as_str() {
        "Write" => p
            .tool_input
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    let event = match p.permission_mode.as_deref() {
        Some(mode) if host == Host::ClaudeCode && MODES_WITHOUT_PROMPT.contains(&mode) => {
            HookEvent::PreToolUseNoAsk
        }
        _ => HookEvent::PreToolUse,
    };
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id),
        call_id: p.tool_use_id,
        cwd: p.cwd,
        tool: p.tool_name,
        action,
        content,
        event,
    })
}

fn map_tool(tool: &str, input: &Value, cwd: Option<&str>) -> Result<Option<Action>, HostError> {
    let field = |name: &'static str| crate::input_str(input, tool, name);
    let action = match tool {
        "Bash" => Action::Shell {
            command: field("command")?,
        },
        "Monitor" => monitor(input)?,
        "PowerShell" => Action::ForeignShell {
            shell: tool.to_owned(),
            command: field("command")?,
        },
        "Read" => Action::FsRead {
            path: field("file_path")?,
        },
        // Claude Code `LSP` answers hover, definition and symbol queries from the file.
        "LSP" => Action::FsRead {
            path: field("filePath")?,
        },
        "Edit" | "Write" | "MultiEdit" => Action::FsWrite {
            path: field("file_path")?,
        },
        // `SendFile` copies each file's contents to another Claude Code session.
        "SendFile" => Action::ReadFiles {
            paths: send_file(input)?,
        },
        "NotebookEdit" => Action::FsWrite {
            path: field("notebook_path")?,
        },
        // `WebFetch` only GETs `url`; the agent cannot attach a body (ADR-017).
        "WebFetch" => Action::Fetch { url: field("url")? },
        // `WebSearch` sends `query` to the host's search provider; `allowed_domains`
        // and `blocked_domains` only filter the results it returns.
        "WebSearch" => Action::WebSearch {
            query: field("query")?,
        },
        // Codex file edits: the patch text names every file it touches.
        "apply_patch" => Action::Patch {
            writes: openmoat_core::patch_writes(&field("command")?),
        },
        "Glob" => crate::glob_roots(input, cwd),
        "Grep" => crate::search_root(input, cwd),
        "ReadMcpResourceTool" => read_mcp_resource(input)?,
        // Entering an existing worktree moves the session, and so the project
        // root, to `path`: read as a directory, so a deny on it holds. A new
        // worktree (`name`) goes under the project's `.claude/worktrees/` and is
        // left to Claude Code, as `Skill` is.
        "EnterWorktree" => match crate::search_path(input) {
            Some(path) => Action::FsRead {
                path: path.to_owned(),
            },
            None => return Ok(None),
        },
        name if name.starts_with("mcp__") => crate::wire::mcp::action(name, input)?,
        _ => return Ok(None),
    };
    Ok(Some(action))
}

/// Claude Code `ReadMcpResourceTool` asks MCP `server` for the resource at
/// `uri`: decided as that server's `read_resource` tool, with a `file:` URI read
/// as the file it names and any other URI as a host it may contact.
fn read_mcp_resource(input: &Value) -> Result<Action, HostError> {
    const TOOL: &str = "ReadMcpResourceTool";
    let server = crate::input_str(input, TOOL, "server")?;
    let uri = crate::input_str(input, TOOL, "uri")?;
    let (reads, hosts) = match openmoat_core::file_url_path(&uri) {
        Some(path) => (vec![path], Vec::new()),
        // A `file:` URI without an absolute path names no file that can be
        // checked, so it is refused.
        None if uri
            .get(..5)
            .is_some_and(|s| s.eq_ignore_ascii_case("file:")) =>
        {
            return Err(HostError::MalformedArguments {
                tool: TOOL.to_owned(),
                problem: format!("`{uri}` is a file URI without an absolute path"),
            });
        }
        None => (Vec::new(), vec![uri]),
    };
    Ok(Action::McpTool {
        name: format!("mcp__{server}__read_resource"),
        reads,
        writes: Vec::new(),
        hosts,
        unchecked: None,
    })
}

/// Claude Code `Monitor` streams the output of a shell `command`, or the frames
/// of a WebSocket `ws.url`; it takes exactly one of them.
fn monitor(input: &Value) -> Result<Action, HostError> {
    const TOOL: &str = "Monitor";
    match (input.get("command"), input.get("ws")) {
        (Some(_), None) => Ok(Action::Shell {
            command: crate::input_str(input, TOOL, "command")?,
        }),
        (None, Some(ws)) => Ok(Action::Net {
            url: crate::input_str(ws, TOOL, "url")?,
        }),
        _ => Err(HostError::MalformedArguments {
            tool: TOOL.to_owned(),
            problem: "needs exactly one of `command` or `ws`".to_owned(),
        }),
    }
}

/// Claude Code `SendFile` `files`: a non-empty list of paths. Claude Code also
/// accepts a lone string as a one-element list, so that is read the same way.
fn send_file(input: &Value) -> Result<Vec<String>, HostError> {
    let malformed = |problem: &str| HostError::MalformedArguments {
        tool: "SendFile".to_owned(),
        problem: problem.to_owned(),
    };
    let paths = match input.get("files") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(list)) => list
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| malformed("`files` holds a value that is not a path"))?,
        _ => return Err(malformed("`files` is not a list of paths")),
    };
    if paths.is_empty() || paths.iter().any(|p| p.is_empty()) {
        return Err(malformed("`files` is empty or names an empty path"));
    }
    Ok(paths.into_iter().map(str::to_owned).collect())
}

pub(crate) fn render(decision: &Decision) -> String {
    // `defer` (ADR-025) is no decision: with nothing on stdout and exit 0 the host
    // runs its own permission flow, as if no hook had answered.
    if decision.verdict == Verdict::Defer {
        return String::new();
    }
    // A `Value` always renders, unlike serializing a struct; its keys sort,
    // and these are already in order.
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": EVENT,
            "permissionDecision": decision.verdict.as_str(),
            "permissionDecisionReason": crate::reason_line(decision),
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests;

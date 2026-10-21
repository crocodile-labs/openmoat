//! GitHub Copilot CLI tools: which action a `preToolUse` call is, from the
//! tool's name and its arguments.
//!
//! The argument shapes are the ones the CLI's own timeline renderer parses in
//! `@github/copilot` 1.0.101 (`cli-main.js`): `view` `{path, view_range}`,
//! `create` `{path, file_text}`, `edit`/`str_replace` `{path, old_str, new_str}`,
//! the older `str_replace_editor` `{command, path, …}`, `apply_patch` (the patch
//! text, or `{input}` / `{patch}` holding it), the shell tools `{command, …}`
//! and `write_<shell>` `{shellId, input}`, `grep`/`rg` and `glob`
//! `{pattern, paths}`. The tool names are those of
//! <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference>
//! ("Tool names").

use openmoat_core::Action;
use serde_json::Value;

use crate::HostError;

/// Tools that change only the session's own state (its to-do list, its
/// intent line, a question to the person) or read the output of a shell the
/// agent already started; `task` starts a subagent whose own tool calls fire
/// `preToolUse`. Recorded and left to Copilot's own permission flow.
const AGENT_STATE_TOOLS: &[&str] = &[
    "ask_user",
    "report_intent",
    "task",
    "think",
    "update_todo",
    "read_bash",
    "stop_bash",
    "list_bash",
    "read_powershell",
    "stop_powershell",
    "list_powershell",
];

/// The action of the `tool` call with arguments `args`, `None` for a tool that
/// touches nothing OpenMoat governs. A tool Copilot does not document is read
/// like an MCP tool: the hook payload does not tell an MCP tool from a built-in
/// one, so every path and URL its arguments name is checked
/// ([`crate::wire::mcp`]).
pub(super) fn action(
    tool: &str,
    args: &Value,
    cwd: Option<&str>,
) -> Result<Option<Action>, HostError> {
    let field = |name: &'static str| crate::input_str(args, tool, name);
    let action = match tool {
        "bash" | "local_shell" => Action::Shell {
            command: field("command")?,
        },
        // `write_bash` types `input` into a shell the agent started earlier.
        "write_bash" => Action::Shell {
            command: field("input")?,
        },
        "powershell" => powershell(field("command")?),
        "write_powershell" => powershell(field("input")?),
        "view" => Action::FsRead {
            path: field("path")?,
        },
        "create" | "edit" | "str_replace" => Action::FsWrite {
            path: field("path")?,
        },
        "str_replace_editor" => match field("command")?.as_str() {
            "view" => Action::FsRead {
                path: field("path")?,
            },
            _ => Action::FsWrite {
                path: field("path")?,
            },
        },
        "apply_patch" => Action::Patch {
            writes: openmoat_core::patch_writes(&patch_text(args)?),
        },
        "grep" | "rg" | "glob" => search(tool, args, cwd)?,
        // `web_fetch` only GETs `url` (ADR-017).
        "web_fetch" => Action::Fetch { url: field("url")? },
        "web_search" => Action::WebSearch {
            query: field("query")?,
        },
        name if AGENT_STATE_TOOLS.contains(&name) => return Ok(None),
        other => crate::wire::mcp::action(other, args)?,
    };
    Ok(Some(action))
}

fn powershell(command: String) -> Action {
    Action::ForeignShell {
        shell: "PowerShell".to_owned(),
        command,
    }
}

/// The patch an `apply_patch` call applies: its arguments themselves when they
/// are the text, else their `input` or `patch`, as the CLI reads them.
fn patch_text(args: &Value) -> Result<String, HostError> {
    let text = match args {
        Value::String(text) => Some(text.as_str()),
        other => other
            .get("input")
            .or_else(|| other.get("patch"))
            .and_then(Value::as_str),
    };
    text.filter(|t| !t.is_empty())
        .map(str::to_owned)
        .ok_or(HostError::MissingField {
            tool: "apply_patch".to_owned(),
            field: "input",
        })
}

/// What a search reads: every directory or file its `paths` (a string or a
/// list) and `path` name, and the directory of an absolute `glob` pattern; the
/// working directory when they name none.
fn search(tool: &str, args: &Value, cwd: Option<&str>) -> Result<Action, HostError> {
    let malformed = || HostError::MalformedArguments {
        tool: tool.to_owned(),
        problem: "`paths` is not a path or a list of paths".to_owned(),
    };
    let mut paths = Vec::new();
    for key in ["paths", "path"] {
        match args.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(one)) => paths.push(one.clone()),
            Some(Value::Array(list)) => {
                for path in list {
                    paths.push(path.as_str().ok_or_else(malformed)?.to_owned());
                }
            }
            Some(_) => return Err(malformed()),
        }
    }
    // A `grep` pattern is a regular expression, not a path.
    if tool == "glob"
        && let Some(dir) = args
            .get("pattern")
            .and_then(Value::as_str)
            .and_then(crate::pattern_dir)
    {
        paths.push(dir);
    }
    paths.retain(|p| !p.is_empty());
    Ok(match paths.len() {
        0 => crate::search_root(args, cwd),
        1 => Action::FsRead {
            path: paths.remove(0),
        },
        _ => Action::ReadFiles { paths },
    })
}

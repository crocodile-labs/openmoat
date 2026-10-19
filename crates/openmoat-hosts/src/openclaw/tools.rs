//! OpenClaw's tools mapped to actions. Tool ids and parameters are those of
//! OpenClaw 2026.10.5 (<https://docs.openclaw.ai/tools>, its `dist` tool schemas).
//! The hook sees every tool, so a tool not named here is an `UnknownTool`:
//! `defaults.tool.unknown` decides it.

use openmoat_core::Action;
use serde_json::Value;

use super::Call;
use crate::HostError;

/// Tools that touch no file, command or network of this machine: recorded and
/// left to OpenClaw.
const UNGOVERNED: &[&str] = &[
    "ask_user",
    "session_status",
    "agents_list",
    "agents_wait",
    "get_goal",
    "create_goal",
    "update_goal",
    "progress_card",
    "theme",
    "screen",
    "wait",
    "tool_search",
    "tool_describe",
    "heartbeat_respond",
];

/// `process` actions that only read or stop a running `exec` session; the
/// others (`send-keys`, `submit`, `paste`, `write`) type into it.
const PROCESS_READS: &[&str] = &["list", "poll", "log", "kill", "clear", "remove"];

/// `plugins` actions that change nothing.
const PLUGINS_READS: &[&str] = &["list", "inspect", "search"];

pub(super) fn map(call: &Call<'_>) -> Result<Option<Action>, HostError> {
    let tool = call.tool;
    let field = |name: &'static str| crate::input_str(call.params, tool, name);
    // Code Mode runs the model's JavaScript through an outer `exec`.
    if call.tool_kind == Some("code_mode_exec") {
        return Ok(Some(Action::ForeignShell {
            shell: "OpenClaw Code Mode".to_owned(),
            command: call.params.to_string(),
        }));
    }
    let action = match tool {
        "exec" => exec(call)?,
        "process" => match field("action")?.as_str() {
            action if PROCESS_READS.contains(&action) => return Ok(None),
            _ => Action::ForeignShell {
                shell: "OpenClaw process input".to_owned(),
                command: call.params.to_string(),
            },
        },
        "read" => match paths(call)?.as_slice() {
            [one] => Action::FsRead { path: one.clone() },
            many => Action::ReadFiles {
                paths: many.to_vec(),
            },
        },
        "write" | "edit" => match paths(call)?.as_slice() {
            [one] => Action::FsWrite { path: one.clone() },
            many => Action::Patch {
                writes: many.to_vec(),
            },
        },
        "apply_patch" => Action::Patch {
            writes: openmoat_core::patch_writes(&field("input")?)
                .into_iter()
                .map(|path| checked(call, path))
                .collect::<Result<_, _>>()?,
        },
        "web_fetch" => Action::Fetch { url: field("url")? },
        "web_search" | "x_search" => Action::WebSearch {
            query: field("query")?,
        },
        "browser" => browser(call)?,
        // `config.get` returns the Gateway's configuration; `update.run`
        // replaces OpenClaw itself.
        "gateway" => match field("action")?.as_str() {
            "config.get" => Action::FsRead {
                path: config_path(call)?,
            },
            "config.schema.lookup" => return Ok(None),
            _ => unknown(call),
        },
        // Installing, enabling, disabling or reloading plugins changes what
        // the Gateway loads: decided as a write to its configuration, which
        // holds OpenMoat's own plugin.
        "plugins" => match field("action")?.as_str() {
            action if PLUGINS_READS.contains(&action) => return Ok(None),
            _ => Action::FsWrite {
                path: config_path(call)?,
            },
        },
        name if UNGOVERNED.contains(&name) => return Ok(None),
        // OpenClaw names an MCP tool `<server>__<tool>`; built-in and plugin
        // tool ids have no `__`.
        name if name.contains("__") => crate::mcp::action(&format!("mcp__{name}"), call.params)?,
        _ => unknown(call),
    };
    Ok(Some(action))
}

fn unknown(call: &Call<'_>) -> Action {
    Action::UnknownTool {
        host: crate::Host::OpenClaw.id().to_owned(),
        tool: call.tool.to_owned(),
    }
}

/// `exec` runs `command` in the user's `SHELL` (PowerShell on Windows), with
/// `env` merged into its environment: written as assignments before the
/// command, so the rules on what a command sets apply to them.
fn exec(call: &Call<'_>) -> Result<Action, HostError> {
    let command = crate::input_str(call.params, call.tool, "command")?;
    if call.windows {
        return Ok(Action::ForeignShell {
            shell: "PowerShell".to_owned(),
            command,
        });
    }
    let mut line = String::new();
    match call.params.get("env") {
        None | Some(Value::Null) => {}
        Some(Value::Object(env)) => {
            for (key, value) in env {
                let value = value.as_str().filter(|_| is_name(key)).ok_or_else(|| {
                    malformed(
                        call,
                        format!("`env` entry `{key}` is not a name and a string"),
                    )
                })?;
                line.push_str(key);
                line.push_str("='");
                line.push_str(&value.replace('\'', r"'\''"));
                line.push_str("' ");
            }
        }
        Some(_) => return Err(malformed(call, "`env` is not an object".to_owned())),
    }
    line.push_str(&command);
    Ok(Action::Shell { command: line })
}

/// The directory `exec` runs in: `workdir`, taken from the workspace when
/// relative, else the workspace.
pub(super) fn workdir(workdir: Option<&Value>, cwd: Option<String>) -> Option<String> {
    match (
        workdir.and_then(Value::as_str).filter(|w| !w.is_empty()),
        cwd,
    ) {
        (Some(dir), _) if !is_relative(dir) => Some(dir.to_owned()),
        (Some(dir), Some(cwd)) => Some(format!("{}/{dir}", cwd.trim_end_matches(['/', '\\']))),
        (_, cwd) => cwd,
    }
}

/// The browser opens or navigates to `url` (or `targetUrl`), and `upload`
/// sends local files to the page. Other actions act on a page already open.
fn browser(call: &Call<'_>) -> Result<Action, HostError> {
    let params = call.params;
    let url = ["url", "targetUrl"]
        .into_iter()
        .find_map(|key| params.get(key).and_then(Value::as_str))
        .filter(|u| !u.is_empty());
    match (crate::input_str(params, call.tool, "action")?.as_str(), url) {
        ("open" | "navigate", Some(url)) => Ok(Action::Net {
            url: url.to_owned(),
        }),
        ("open" | "navigate", None) => Err(HostError::MissingField {
            tool: call.tool.to_owned(),
            field: "url",
        }),
        ("upload", _) => {
            let paths = params
                .get("paths")
                .and_then(Value::as_array)
                .map(|list| list.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
                .unwrap_or_default()
                .filter(|p| !p.is_empty() && p.iter().all(|s| !s.is_empty()))
                .ok_or_else(|| malformed(call, "`paths` is not a list of paths".to_owned()))?;
            Ok(Action::ReadFiles {
                paths: paths
                    .into_iter()
                    .map(|p| checked(call, p.to_owned()))
                    .collect::<Result<_, _>>()?,
            })
        }
        _ => Ok(unknown(call)),
    }
}

/// The file tools take `path`; their renderers also read `file_path`, so both
/// are checked when present.
fn paths(call: &Call<'_>) -> Result<Vec<String>, HostError> {
    let mut found: Vec<String> = Vec::new();
    for key in ["path", "file_path"] {
        match call.params.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(path)) if !path.is_empty() => {
                let path = checked(call, path.clone())?;
                if !found.contains(&path) {
                    found.push(path);
                }
            }
            Some(_) => return Err(malformed(call, format!("`{key}` is not a path"))),
        }
    }
    if found.is_empty() {
        return Err(HostError::MissingField {
            tool: call.tool.to_owned(),
            field: "path",
        });
    }
    Ok(found)
}

/// A relative path is resolved against the workspace; without one, which
/// file it names is unknown.
fn checked(call: &Call<'_>, path: String) -> Result<String, HostError> {
    if is_relative(&path) && call.cwd.is_none() {
        return Err(malformed(
            call,
            format!("`{path}` is relative and the payload names no workspace (`cwd`)"),
        ));
    }
    Ok(path)
}

fn config_path(call: &Call<'_>) -> Result<String, HostError> {
    call.config_path
        .map(str::to_owned)
        .ok_or(HostError::MissingField {
            tool: call.tool.to_owned(),
            field: "configPath",
        })
}

fn is_relative(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !(drive || path.starts_with(['/', '\\', '~']))
}

fn is_name(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn malformed(call: &Call<'_>, problem: String) -> HostError {
    HostError::MalformedArguments {
        tool: call.tool.to_owned(),
        problem,
    }
}

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

/// `cron` actions that only read the scheduler, its jobs and their runs.
const CRON_READS: &[&str] = &["status", "list", "get", "runs"];
/// `cron` actions that store work the Gateway runs later: a job (`add`,
/// `update`) or a job's next run (`next_check`). A job's payload is an agent
/// turn, a system event, a script, or a command that "execute\[s\] directly in
/// the Gateway process, not as an agent `tools.exec` tool call"
/// (<https://docs.openclaw.ai/cli/cron>), so no later hook sees it.
const CRON_SCHEDULES: &[&str] = &["add", "update", "next_check"];

/// `nodes` actions that read the state of paired devices or of their pairing
/// (<https://github.com/openclaw/openclaw/blob/main/src/agents/tools/nodes-tool.ts>).
/// Media capture, location, notifications, pairing approval and the other
/// actions act on the device or its owner: `tool.unknown`.
const NODES_READS: &[&str] = &[
    "status",
    "describe",
    "pending",
    "camera_list",
    "device_status",
    "device_info",
    "device_permissions",
    "device_health",
    "which",
];

/// OpenClaw's control-plane database in its state directory, which holds its
/// automation jobs, approvals and plugin state
/// (<https://docs.openclaw.ai/reference/database-schemas/layout>).
const STATE_DATABASE: &str = "state/openclaw.sqlite";

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
        // A job runs later from the Gateway, outside any hook: decided as a
        // write to the database it is stored in, which `runs-later` asks for.
        "cron" => match field("action")?.as_str() {
            action if CRON_READS.contains(&action) => return Ok(None),
            action if CRON_SCHEDULES.contains(&action) => Action::FsWrite {
                path: state_database(call)?,
            },
            _ => unknown(call),
        },
        "nodes" => return nodes(call),
        "view_image" => return view_image(call),
        name if UNGOVERNED.contains(&name) => return Ok(None),
        // OpenClaw names an MCP tool `<server>__<tool>`; built-in and plugin
        // tool ids have no `__`.
        name if name.contains("__") => {
            crate::wire::mcp::action(&format!("mcp__{name}"), call.params)?
        }
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
    if let Some(dir) = home_workdir(call.params.get("workdir")) {
        line = format!("{dir} && {line}");
    }
    Ok(Action::Shell { command: line })
}

/// A `workdir` under the home directory (`~`, `~/x`), which OpenClaw expands
/// itself, as a `cd` to put before the command: the guard takes a working
/// directory literally, so `~/.ssh` would be a directory named `~` in its own.
/// The rest of the path is quoted, so only the `~` is expanded.
fn home_workdir(workdir: Option<&Value>) -> Option<String> {
    let dir = workdir.and_then(Value::as_str)?;
    let rest = match dir.strip_prefix('~')? {
        "" => return Some("cd ~".to_owned()),
        rest if rest.starts_with(['/', '\\']) => &rest[1..],
        _ => return None,
    };
    Some(format!("cd ~/'{}'", rest.replace('\'', r"'\''")))
}

/// The directory `exec` runs in: `workdir`, taken from the workspace when
/// relative, else the workspace. A `workdir` under `~` is the workspace here
/// and a `cd` in the command ([`home_workdir`]).
pub(super) fn workdir(workdir: Option<&Value>, cwd: Option<String>) -> Option<String> {
    if home_workdir(workdir).is_some() {
        return cwd;
    }
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

/// `nodes` acts on paired devices. `invoke` relays `invokeCommand` to one,
/// where it runs and no rule of this machine applies: a shell OpenMoat cannot
/// read. OpenClaw keeps `system.run` out of `invoke`; a command on a node goes
/// through `exec` with `host=node` (<https://docs.openclaw.ai/nodes/node-exec>),
/// which is checked as a command. A capture saved to `outPath` is a write of it.
fn nodes(call: &Call<'_>) -> Result<Option<Action>, HostError> {
    let action = crate::input_str(call.params, call.tool, "action")?;
    if NODES_READS.contains(&action.as_str()) {
        return Ok(None);
    }
    if action == "invoke" {
        crate::input_str(call.params, call.tool, "invokeCommand")?;
        return Ok(Some(Action::ForeignShell {
            shell: "OpenClaw node command".to_owned(),
            command: call.params.to_string(),
        }));
    }
    match call.params.get("outPath") {
        None | Some(Value::Null) => Ok(Some(unknown(call))),
        Some(Value::String(path)) if !path.is_empty() => Ok(Some(Action::FsWrite {
            path: checked(call, path.clone())?,
        })),
        Some(_) => Err(malformed(call, "`outPath` is not a path".to_owned())),
    }
}

/// `view_image` shows the model `path` or each of `paths`: a local image or a
/// URL OpenClaw permits (<https://docs.openclaw.ai/tools>, "Media"). Local
/// files are read; a URL alone is fetched; an inline `data:` image touches
/// nothing. Several URLs alone name no one host: `tool.unknown`.
fn view_image(call: &Call<'_>) -> Result<Option<Action>, HostError> {
    let mut entries: Vec<String> = Vec::new();
    match call.params.get("path") {
        None | Some(Value::Null) => {}
        Some(Value::String(path)) if !path.is_empty() => entries.push(path.clone()),
        Some(_) => return Err(malformed(call, "`path` is not a path".to_owned())),
    }
    match call.params.get("paths") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            for item in list {
                match item.as_str().filter(|p| !p.is_empty()) {
                    Some(path) => entries.push(path.to_owned()),
                    None => {
                        return Err(malformed(call, "`paths` is not a list of paths".to_owned()));
                    }
                }
            }
        }
        Some(_) => return Err(malformed(call, "`paths` is not a list of paths".to_owned())),
    }
    if entries.is_empty() {
        return Err(HostError::MissingField {
            tool: call.tool.to_owned(),
            field: "path",
        });
    }
    let scheme = |entry: &str, prefix: &str| {
        entry
            .get(..prefix.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
    };
    let mut files = Vec::new();
    let mut urls = Vec::new();
    for entry in entries {
        if scheme(&entry, "data:") {
            continue;
        }
        if scheme(&entry, "http://") || scheme(&entry, "https://") {
            urls.push(entry);
        } else if scheme(&entry, "file://") {
            files.push(checked(call, entry["file://".len()..].to_owned())?);
        } else {
            files.push(checked(call, entry)?);
        }
    }
    Ok(match (files.as_slice(), urls.as_slice()) {
        ([], []) => None,
        ([], [url]) => Some(Action::Fetch { url: url.clone() }),
        ([], _) => Some(unknown(call)),
        ([one], _) => Some(Action::FsRead { path: one.clone() }),
        (many, _) => Some(Action::ReadFiles {
            paths: many.to_vec(),
        }),
    })
}

/// OpenClaw's control-plane database: in `stateDir`, or beside `configPath`
/// for a plugin from before the plugin sent `stateDir` (the default layout
/// keeps the configuration in the state directory).
fn state_database(call: &Call<'_>) -> Result<String, HostError> {
    let missing = || HostError::MissingField {
        tool: call.tool.to_owned(),
        field: "stateDir",
    };
    let dir = match (call.state_dir, call.config_path) {
        (Some(dir), _) => dir.trim_end_matches(['/', '\\']),
        (None, Some(config)) => config.rsplit_once(['/', '\\']).ok_or_else(missing)?.0,
        (None, None) => return Err(missing()),
    };
    if dir.is_empty() || is_relative(dir) {
        return Err(missing());
    }
    Ok(format!("{dir}/{STATE_DATABASE}"))
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

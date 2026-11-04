//! Cline's tools mapped to actions. Tool names and inputs are those of
//! `cline/cline` `cli-v3.0.74` (`sdk/packages/core/src/extensions/tools/`:
//! `constants.ts`, `schemas.ts`, `helpers.ts`). The hook sees each tool's
//! arguments as the model gave them, before Cline's lenient schemas
//! (`ReadFilesInputUnionSchema`, `RunCommandsInputUnionSchema`) turn the many
//! shapes they accept into one, so every shape they accept is read here and
//! any other is malformed. The hook runs for every tool, so a tool not named
//! here is checked by what its arguments name: a `<server>__<tool>` name as an
//! MCP tool ([`crate::wire::unknown::mcp`]), any other as an unknown tool.

use openmoat_core::Action;
use serde_json::Value;

use super::Call;
use crate::HostError;

/// Tools that only talk to the person or end the run.
const UNGOVERNED: &[&str] = &["ask_question", "submit_and_exit"];

/// What one call is, and the name to record when it is not Cline's own.
pub(super) struct Mapped {
    /// The action, or `None` for a tool OpenMoat does not govern.
    pub action: Option<Action>,
    /// `mcp__<server>__<tool>` for an MCP server's tool.
    pub tool: Option<String>,
}

impl Mapped {
    fn action(action: Action) -> Self {
        Self {
            action: Some(action),
            tool: None,
        }
    }
}

pub(super) fn map(call: &Call<'_>) -> Result<Mapped, HostError> {
    let tool = call.tool;
    let action = match tool {
        "run_commands" => commands(call)?,
        "read_files" => read(call)?,
        // `editor` replaces text in `path`, inserts at a line, or creates it.
        "editor" => Action::FsWrite {
            path: path(call, &crate::input_str(call.input, tool, "path")?)?,
        },
        "apply_patch" => Action::Patch {
            writes: openmoat_core::patch_writes(&patch_text(call)?),
        },
        // Searches the workspace with each regex of `queries`.
        "search_codebase" => Action::FsRead {
            path: call
                .cwd
                .map(str::to_owned)
                .ok_or_else(|| malformed(call, "the payload names no workspace root".to_owned()))?,
        },
        "fetch_web_content" => fetch(call)?,
        name if UNGOVERNED.contains(&name) => {
            return Ok(Mapped {
                action: None,
                tool: None,
            });
        }
        // `<server>__<tool>`, the name sanitised and, when long, cut and
        // hashed (`defaultMcpToolNameTransform`); a plugin's tool may look
        // the same, so its arguments are checked as an unknown tool's too.
        name if name.contains("__") => {
            let mcp = format!("mcp__{name}");
            let action = mcp_action(&mcp, call.input)?;
            return Ok(Mapped {
                action: Some(action),
                tool: Some(mcp),
            });
        }
        _ => crate::wire::unknown::action(crate::Host::Cline, tool, call.input)?,
    };
    Ok(Mapped::action(action))
}

/// `mcp__<server>__<tool>`: a call that only opens one web page (a browser
/// server's `navigate`, ADR-047) is that MCP tool's page open, as on every
/// other host; any other is decided as the MCP tool with everything its
/// arguments name checked, since a plugin's tool may be named the same way.
fn mcp_action(name: &str, input: &Value) -> Result<Action, HostError> {
    match crate::wire::mcp::action(name, input)? {
        open @ Action::McpTool { .. } if opens_a_page(&open) => Ok(open),
        _ => crate::wire::unknown::mcp(name, input),
    }
}

fn opens_a_page(action: &Action) -> bool {
    matches!(action, Action::McpTool { opens, .. } if !opens.is_empty())
}

/// One command of `run_commands`: a shell line, or a program and its
/// arguments run without a shell.
enum Command {
    Line(String),
    Direct(String, Vec<String>),
}

/// The commands of `run_commands`, in every shape `RunCommandsInputUnionSchema`
/// accepts (`collectRunCommands` in `helpers.ts`).
fn command_list(call: &Call<'_>) -> Result<Vec<Command>, HostError> {
    let input = call.input;
    let list = match input {
        Value::String(_) | Value::Array(_) => entries(call, input)?,
        Value::Object(o) => match (o.get("commands"), o.get("command"), o.get("cmd")) {
            (Some(commands), _, _) => entries(call, commands)?,
            (None, Some(_), _) => vec![entry(call, input)?],
            (None, None, Some(Value::String(line))) => vec![Command::Line(line.clone())],
            _ => return Err(malformed(call, "no `commands`".to_owned())),
        },
        _ => return Err(malformed(call, "the arguments are not an object".to_owned())),
    };
    if list.is_empty() {
        return Err(malformed(call, "`commands` is empty".to_owned()));
    }
    Ok(list)
}

/// A string, an entry, or a list of them.
fn entries(call: &Call<'_>, value: &Value) -> Result<Vec<Command>, HostError> {
    match value {
        Value::Array(items) => items.iter().map(|item| entry(call, item)).collect(),
        other => Ok(vec![entry(call, other)?]),
    }
}

/// A shell line, or `{command, args}`: with `args` (even empty) the program
/// runs directly; without, `command` is a shell line.
fn entry(call: &Call<'_>, value: &Value) -> Result<Command, HostError> {
    match value {
        Value::String(line) => Ok(Command::Line(line.clone())),
        Value::Object(o) => {
            let Some(Value::String(command)) = o.get("command") else {
                return Err(malformed(call, "a command is not a string".to_owned()));
            };
            match o.get("args") {
                None => Ok(Command::Line(command.clone())),
                Some(Value::Array(args)) => {
                    let args = args
                        .iter()
                        .map(|a| a.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| malformed(call, "an argument is not a string".to_owned()))?;
                    Ok(Command::Direct(command.clone(), args))
                }
                Some(_) => Err(malformed(call, "`args` is not a list".to_owned())),
            }
        }
        _ => Err(malformed(call, "a command is not a string".to_owned())),
    }
}

/// `run_commands`: each command runs on its own, in the workspace. One shell
/// line is decided as it is; several are decided together, each in a
/// subshell of its own, so a `cd` in one does not move the next. A line that
/// cannot be read on its own (an open quote, a trailing `\`) could hide the
/// next one when they are put together, so then the call at least needs
/// review. On Windows the lines run in PowerShell, which OpenMoat cannot read.
fn commands(call: &Call<'_>) -> Result<Action, HostError> {
    let list = command_list(call)?;
    let lines: Vec<String> = list
        .iter()
        .map(|c| match c {
            Command::Line(line) => line.clone(),
            Command::Direct(program, args) => std::iter::once(program)
                .chain(args)
                .map(|w| quote(w))
                .collect::<Vec<_>>()
                .join(" "),
        })
        .collect();
    let shell_lines = list.iter().any(|c| matches!(c, Command::Line(_)));
    if call.windows && shell_lines {
        return Ok(Action::ForeignShell {
            shell: "PowerShell".to_owned(),
            command: lines.join("\n"),
        });
    }
    if let [line] = lines.as_slice() {
        return Ok(Action::Shell {
            command: line.clone(),
        });
    }
    let readable = lines.iter().all(|line| {
        openmoat_core::lexer::lex(line).is_ok() && !line.trim_end().ends_with('\\')
    });
    let command = lines
        .iter()
        .map(|line| format!("(\n{line}\n)"))
        .collect::<Vec<_>>()
        .join("\n");
    let action = Action::Shell { command };
    if readable {
        Ok(action)
    } else {
        Ok(Action::unchecked(
            action,
            "Cline runs each of its commands on its own, and one of them cannot be read alone",
        ))
    }
}

/// `word` as one POSIX shell word: as it is when it holds nothing a shell
/// reads, else in single quotes.
fn quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./=:@%+,".contains(c));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// The keys a file request may name its path by (`LooseReadFileRequestSchema`).
const PATH_KEYS: &[&str] = &["path", "file_path", "filePath"];

/// `read_files`, in every shape `ReadFilesInputUnionSchema` accepts: a path,
/// a request (`{path, start_line, end_line}`), a list of either, or one of
/// those under `files`, `file_paths` or `paths`.
fn read(call: &Call<'_>) -> Result<Action, HostError> {
    let input = call.input;
    let listed = match input {
        Value::Object(o) if PATH_KEYS.iter().any(|k| o.contains_key(*k)) => input,
        Value::Object(o) => ["files", "file_paths", "paths"]
            .iter()
            .find_map(|k| o.get(*k))
            .ok_or_else(|| malformed(call, "no `files`".to_owned()))?,
        other => other,
    };
    let requests = match listed {
        Value::Array(items) => items.iter().collect(),
        one => vec![one],
    };
    let mut paths = Vec::with_capacity(requests.len());
    for request in requests {
        let raw = match request {
            Value::String(p) => p,
            Value::Object(o) => PATH_KEYS
                .iter()
                .find_map(|k| o.get(*k).and_then(Value::as_str))
                .ok_or_else(|| malformed(call, "a file request has no `path`".to_owned()))?,
            _ => return Err(malformed(call, "a file request is not a path".to_owned())),
        };
        let path = path(call, raw)?;
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    match paths.len() {
        0 => Err(malformed(call, "`files` is empty".to_owned())),
        1 => Ok(Action::FsRead {
            path: paths.remove(0),
        }),
        _ => Ok(Action::ReadFiles { paths }),
    }
}

/// `apply_patch`: `{input}` or the patch itself.
fn patch_text(call: &Call<'_>) -> Result<String, HostError> {
    match call.input {
        Value::String(text) => Ok(text.clone()),
        _ => crate::input_str(call.input, call.tool, "input"),
    }
}

/// `fetch_web_content`: `requests`, each a URL Cline GETs and has the model
/// read (`executors/web-fetch.ts`). One URL is a `Fetch`; several are checked
/// together as the hosts of an unknown tool.
fn fetch(call: &Call<'_>) -> Result<Action, HostError> {
    let Some(Value::Array(requests)) = call.input.get("requests") else {
        return Err(malformed(call, "`requests` is not a list".to_owned()));
    };
    let urls = requests
        .iter()
        .map(|r| r.get("url").and_then(Value::as_str))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| malformed(call, "a request has no `url`".to_owned()))?;
    match urls.as_slice() {
        [] => Err(malformed(call, "`requests` is empty".to_owned())),
        [url] => Ok(Action::Fetch {
            url: (*url).to_owned(),
        }),
        _ => crate::wire::unknown::action(crate::Host::Cline, call.tool, call.input),
    }
}

/// A path as the tool gives it: Cline asks for absolute paths; a relative one
/// resolves in the workspace, so it needs one.
fn path(call: &Call<'_>, raw: &str) -> Result<String, HostError> {
    if raw.is_empty() {
        return Err(malformed(call, "a path is empty".to_owned()));
    }
    let absolute = raw.starts_with(['/', '\\', '~'])
        || (raw.len() >= 2 && raw.as_bytes()[0].is_ascii_alphabetic() && raw.as_bytes()[1] == b':');
    if !absolute && call.cwd.is_none() {
        return Err(malformed(
            call,
            format!("`{raw}` is relative and the payload names no workspace root"),
        ));
    }
    Ok(raw.to_owned())
}

fn malformed(call: &Call<'_>, problem: String) -> HostError {
    HostError::MalformedArguments {
        tool: call.tool.to_owned(),
        problem,
    }
}

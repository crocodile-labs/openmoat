//! Hermes Agent tools: which action a `pre_tool_call` is, from the tool's name
//! and its arguments.
//!
//! The argument shapes are the tools' own schemas in v0.22.5:
//! `tools/terminal_tool.py` (`terminal`), `tools/file_tools.py` (`read_file`,
//! `write_file`, `patch`, `search_files`), `tools/web_tools.py`,
//! `tools/browser_tool.py`, `tools/code_execution_tool.py`,
//! `tools/process_registry.py` (`process_manage`), `tools/cronjob_tools.py`,
//! and `tools/mcp_tool_schema.py` for the names of MCP tools.
//!
//! Hermes resolves a relative path against the session's working directory
//! (`tools/file_tools_paths.py`: the directory the session's terminal last
//! moved to, or the workspace a Desktop, TUI or ACP session registered), which
//! the hook payload does not send: its `cwd` is the Hermes process's. A file
//! tool's relative path is therefore checked against that `cwd` and asks.

use openmoat_core::Action;
use serde_json::Value;

use crate::{Host, HostError};

/// Tools that change only the session's own state (its to-do list, a question
/// to the person, a search of its own past sessions, the skill list) or read
/// or end a terminal session the agent started; `delegate_task` starts
/// subagents, whose own tool calls fire `pre_tool_call` in the same process.
/// Recorded and left to Hermes.
const AGENT_STATE_TOOLS: &[&str] = &[
    "todo_list",
    "clarify",
    "session_search",
    "skills_list",
    "delegate_task",
    "read_terminal",
    "close_terminal",
];

/// `process_manage` actions that only look at or stop a background process
/// the agent started; `write` and `submit` type into it.
const PROCESS_READS: &[&str] = &["list", "poll", "log", "wait", "kill", "close", "handoff"];

/// What the payload does not show about a relative path.
const RELATIVE: &str = "Hermes Agent resolves a relative path against the session's working \
     directory, which its hook does not send (it sends the Hermes process's)";

/// The action of the `tool` call with arguments `args` (an object), `None`
/// for a tool that touches nothing OpenMoat governs. A tool not named here
/// is an unknown tool: every path, URL and command its arguments name is
/// checked ([`crate::wire::unknown`]).
pub(super) fn action(tool: &str, args: &Value) -> Result<Option<Action>, HostError> {
    let field = |name: &'static str| crate::input_str(args, tool, name);
    let action = match tool {
        "terminal" => terminal(field("command")?, args.get("workdir")),
        "read_file" => checked(Action::FsRead {
            path: field("path")?,
        }),
        "write_file" => checked(Action::FsWrite {
            path: field("path")?,
        }),
        "patch" => patch(args)?,
        "search_files" => search(args),
        "web_search" => Action::WebSearch {
            query: field("query")?,
        },
        "web_extract" => extract(args)?,
        // The browser loads the page: a request that runs the page's scripts.
        "browser_navigate" => Action::Net { url: field("url")? },
        // A Python script the classifier cannot read; the tool calls it
        // makes through `hermes_tools` fire `pre_tool_call` one by one.
        "execute_code" => Action::ForeignShell {
            shell: "Python (execute_code)".to_owned(),
            command: field("code")?,
        },
        "process_manage" => match field("action")?.as_str() {
            read if PROCESS_READS.contains(&read) => return Ok(None),
            // Typed into a process the agent started earlier, which joins it
            // to what came before: checked as a command, and it asks.
            _ => Action::unchecked(
                Action::Shell {
                    command: field("data")?,
                },
                "input typed into a running process joins what was typed before, which this \
                 call does not show",
            ),
        },
        // A scheduled job runs the agent later, unattended, with the prompt,
        // skills and script this call sets.
        "cronjob_manage" => match field("action")?.as_str() {
            "list" => return Ok(None),
            _ => Action::unchecked(
                crate::wire::unknown::action(Host::Hermes, tool, args)?,
                "a scheduled job runs the agent later, unattended",
            ),
        },
        // `memory` changes the notes Hermes puts into every later session's
        // prompt (`memories/` in its home), `skill_manage` a skill it loads
        // into later sessions (`skills/`): writes there, which the taint list
        // and `runs-later` ask about. Named under the default home, whose
        // patterns cover a moved one.
        "memory" => Action::FsWrite {
            path: MEMORIES.to_owned(),
        },
        "skill_manage" => skills(args),
        name if name.starts_with("mcp__") => crate::wire::mcp::action(name, args)?,
        name if AGENT_STATE_TOOLS.contains(&name) => return Ok(None),
        // `skill_view`, the other browser tools,
        // `vision_analyze`, the messaging tools, connectors and a plugin's tools;
        // `tool_call` only when Hermes could not unwrap it.
        other => crate::wire::unknown::action(Host::Hermes, other, args)?,
    };
    Ok(Some(action))
}

/// The memory folder of Hermes Agent's home, whose files `memory` writes.
const MEMORIES: &str = "~/.hermes/memories";
/// The skills folder of Hermes Agent's home that `skill_manage` writes in.
const SKILLS: &str = "~/.hermes/skills";

/// What `skill_manage` writes: the folder in [`SKILLS`] of each skill its
/// `operations` (or a lone `name`) name as one plain path segment, else the
/// folder of every skill. The same rules apply to both; the names only make
/// the record clearer.
fn skills(args: &Value) -> Action {
    let mut names: Vec<String> = match args.get("operations").and_then(Value::as_array) {
        Some(operations) => operations
            .iter()
            .map(skill_name)
            .collect::<Option<_>>()
            .unwrap_or_default(),
        None => skill_name(args).into_iter().collect(),
    };
    names.sort();
    names.dedup();
    let mut writes: Vec<String> = names.iter().map(|n| format!("{SKILLS}/{n}")).collect();
    match writes.len() {
        0 => Action::FsWrite {
            path: SKILLS.to_owned(),
        },
        1 => Action::FsWrite {
            path: writes.remove(0),
        },
        _ => Action::Patch { writes },
    }
}

/// The `name` of a `skill_manage` operation when it is one plain path segment.
fn skill_name(operation: &Value) -> Option<String> {
    let name = operation.get("name").and_then(Value::as_str)?;
    let plain = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0']);
    plain.then(|| name.to_owned())
}

/// `terminal` runs `command` in the session's persistent bash (Git Bash on
/// Windows), in `workdir` when given: written as a `cd` before the command.
/// The shell stays where a `cd` leaves it for the session's later commands,
/// so a command that leaves it where OpenMoat cannot know asks
/// ([`openmoat_core::leaves_unknown_directory`]), as does one with a relative
/// `workdir`.
fn terminal(command: String, workdir: Option<&Value>) -> Action {
    let moves = openmoat_core::leaves_unknown_directory(&command);
    let dir = workdir.and_then(Value::as_str).filter(|d| !d.trim().is_empty());
    let line = match dir {
        Some(dir) => format!("cd {} && {command}", quoted_dir(dir)),
        None => command,
    };
    let shell = Action::Shell { command: line };
    if dir.is_some_and(|d| !rooted(d)) {
        Action::unchecked(shell, RELATIVE)
    } else if moves {
        Action::unchecked(
            shell,
            "the command leaves the session's shell, which later commands reuse, in a \
             directory OpenMoat cannot know",
        )
    } else {
        shell
    }
}

/// `dir` quoted for the shell, a leading `~` kept so the shell expands it.
fn quoted_dir(dir: &str) -> String {
    let quote = |s: &str| format!("'{}'", s.replace('\'', r"'\''"));
    match dir.strip_prefix('~') {
        Some("") => "~".to_owned(),
        Some(rest) if rest.starts_with('/') => format!("~/{}", quote(&rest[1..])),
        _ => quote(dir),
    }
}

/// Whether `path` names its place without the session's directory: absolute
/// (`/`, `C:\`, `\\server`) or in the home directory (`~`).
fn rooted(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(['/', '\\', '~'])
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

/// A file tool's action, asking when its path is relative.
fn checked(action: Action) -> Action {
    let relative = match &action {
        Action::FsRead { path } | Action::FsWrite { path } => !rooted(path),
        Action::ReadFiles { paths } => paths.iter().any(|p| !rooted(p)),
        Action::Patch { writes } => writes.iter().any(|p| !rooted(p)),
        _ => false,
    };
    if relative {
        Action::unchecked(action, RELATIVE)
    } else {
        action
    }
}

/// `patch` replaces text in `path`, or with `mode: patch` applies a V4A
/// multi-file patch (the `*** Begin Patch` envelope Codex's `apply_patch`
/// uses), which writes every file it adds, updates, deletes or moves to.
fn patch(args: &Value) -> Result<Action, HostError> {
    let field = |name: &'static str| crate::input_str(args, "patch", name);
    let mode = args.get("mode").and_then(Value::as_str).unwrap_or("replace");
    Ok(checked(match mode {
        "patch" => {
            let writes = openmoat_core::patch_writes(&field("patch")?);
            if writes.is_empty() {
                return Err(HostError::MalformedArguments {
                    tool: "patch".to_owned(),
                    problem: "`patch` names no file".to_owned(),
                });
            }
            Action::Patch { writes }
        }
        _ => Action::FsWrite {
            path: field("path")?,
        },
    }))
}

/// `search_files` reads `path` (the session's directory when absent); for a
/// file search (`target: files`), also where a relative `pattern` climbs to.
fn search(args: &Value) -> Action {
    let root = crate::search_path(args).unwrap_or(".");
    let mut paths = vec![root.to_owned()];
    let files = args.get("target").and_then(Value::as_str) == Some("files");
    let pattern = args.get("pattern").and_then(Value::as_str);
    if files && let Some(pattern) = pattern {
        paths.extend(crate::glob_reach(root, pattern));
    }
    let action = match paths.len() {
        1 => Action::FsRead {
            path: paths.remove(0),
        },
        _ => Action::ReadFiles { paths },
    };
    let action = match pattern {
        Some(pattern) if files => crate::bounded(action, [pattern]),
        _ => action,
    };
    checked(action)
}

/// `web_extract` reads each of `urls` (at most five) without a body: one is a
/// fetch; several are an unknown tool whose every URL is checked.
fn extract(args: &Value) -> Result<Action, HostError> {
    let malformed = |problem: &str| HostError::MalformedArguments {
        tool: "web_extract".to_owned(),
        problem: problem.to_owned(),
    };
    let urls = args
        .get("urls")
        .and_then(Value::as_array)
        .ok_or(HostError::MissingField {
            tool: "web_extract".to_owned(),
            field: "urls",
        })?;
    let urls: Vec<&str> = urls
        .iter()
        .map(|u| u.as_str().filter(|u| !u.is_empty()))
        .collect::<Option<_>>()
        .ok_or_else(|| malformed("`urls` is not a list of URLs"))?;
    match urls.as_slice() {
        [] => Err(malformed("`urls` is empty")),
        [url] => Ok(Action::Fetch {
            url: (*url).to_owned(),
        }),
        _ => crate::wire::unknown::action(Host::Hermes, "web_extract", args),
    }
}

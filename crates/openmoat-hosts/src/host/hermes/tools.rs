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
//! the hook payload does not send: its `cwd` is the Hermes process's, where the
//! terminal starts. A file tool's relative path is checked against that `cwd`.
//! What would make it land elsewhere needs review instead: a relative path
//! that climbs out of it (`..`), and a `terminal` call that leaves the
//! session's shell outside it (a `cd` or `workdir` elsewhere), after which
//! every relative path would resolve there.

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

/// What the payload does not show about a relative directory.
const RELATIVE: &str = "Hermes Agent resolves a relative path against the session's working \
     directory, which its hook does not send (it sends the Hermes process's)";

/// What the payload does not show about the relative `path` a call reads or writes.
fn relative_escapes(path: &str, verb: &str) -> String {
    format!(
        "{verb} `{path}`, which climbs out of the directory Hermes Agent resolves it against \
         (the session's working directory, which its hook does not send)"
    )
}

/// What a `terminal` call that leaves the session's shell outside `cwd` hides.
pub(super) const MOVES_OUT: &str = "the command leaves the session's shell outside the directory Hermes \
     Agent was started in, and later relative file paths would resolve there";

/// The action of the `tool` call with arguments `args` (an object), `None`
/// for a tool that touches nothing OpenMoat governs; `cwd` is the payload's.
/// A tool not named here is an unknown tool: every path, URL and command its
/// arguments name is checked ([`crate::wire::unknown`]).
pub(super) fn action(
    tool: &str,
    args: &Value,
    cwd: Option<&str>,
) -> Result<Option<Action>, HostError> {
    let field = |name: &'static str| crate::input_str(args, tool, name);
    let action = match tool {
        "terminal" => terminal(field("command")?, args.get("workdir"), cwd),
        "read_file" => checked(
            Action::FsRead {
                path: field("path")?,
            },
            cwd,
        ),
        "write_file" => checked(
            Action::FsWrite {
                path: field("path")?,
            },
            cwd,
        ),
        "patch" => checked(patch(args)?, cwd),
        "search_files" => checked(search(args), cwd),
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
            // to what came before: checked as a command, and it needs review.
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
        // and `runs-later` hold for review. Named under the default home, whose
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
/// so a command that leaves it where OpenMoat cannot know needs review
/// ([`openmoat_core::leaves_unknown_directory`]), as does one with a relative
/// `workdir`, and one that leaves it outside `cwd`, against which later
/// relative file paths are checked.
fn terminal(command: String, workdir: Option<&Value>, cwd: Option<&str>) -> Action {
    let moves = openmoat_core::leaves_unknown_directory(&command);
    let dir = workdir.and_then(Value::as_str).filter(|d| !d.trim().is_empty());
    let out = cwd.is_some_and(|cwd| {
        dir.is_some_and(|d| !crate::request::is_inside(d, cwd)) || cds_outside(&command, cwd)
    });
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
    } else if out {
        Action::unchecked(shell, MOVES_OUT)
    } else {
        shell
    }
}

/// Whether a `cd` or `pushd` of `command` outside a subshell moves the shell
/// to a written-out directory that is not `cwd` or below it: elsewhere by an
/// absolute or `~` path, climbing out by `..`, or home with no target. One
/// that cannot be read counts.
fn cds_outside(command: &str, cwd: &str) -> bool {
    use openmoat_core::lexer::{Operator, Token, lex};
    let Ok(tokens) = lex(command) else {
        return true;
    };
    let mut depth = 0_usize;
    let mut words: Vec<&str> = Vec::new();
    let outside = |words: &[&str]| match words {
        ["cd" | "pushd", rest @ ..] => match rest.iter().find(|w| !w.starts_with('-')) {
            None => rest.is_empty() || rest.iter().all(|w| *w != "-"),
            Some(target) if rooted(target) => !crate::request::is_inside(target, cwd),
            Some(target) => climbs(target),
        },
        _ => false,
    };
    for token in &tokens {
        match token {
            Token::Word(word) => words.push(&word.text),
            Token::Operator(Operator::OpenParen) => {
                depth += 1;
                words.clear();
            }
            Token::Operator(Operator::CloseParen) => {
                depth = depth.saturating_sub(1);
                words.clear();
            }
            Token::Operator(op) if op.is_separator() => {
                if depth == 0 && outside(&words) {
                    return true;
                }
                words.clear();
            }
            _ => {}
        }
    }
    depth == 0 && outside(&words)
}

/// Whether the relative `path` climbs above where it starts (`../x`, `a/../../x`).
fn climbs(path: &str) -> bool {
    let mut depth = 0_i64;
    for segment in path.split(['/', '\\']) {
        if segment == ".." {
            depth -= 1;
            if depth < 0 {
                return true;
            }
        } else if !segment.is_empty() && segment != "." {
            depth += 1;
        }
    }
    false
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

/// A file tool's action, checked against the payload's `cwd`. It needs review
/// when one of its relative paths climbs out of that directory, or, with no
/// `cwd` to check against, when one is relative at all; the reason names the
/// path and whether it is read or written.
fn checked(action: Action, cwd: Option<&str>) -> Action {
    let (paths, verb): (&[String], &str) = match &action {
        Action::FsRead { path } => (std::slice::from_ref(path), "reads"),
        Action::FsWrite { path } => (std::slice::from_ref(path), "writes"),
        Action::ReadFiles { paths } => (paths, "reads"),
        Action::Patch { writes } => (writes, "writes"),
        _ => (&[], ""),
    };
    let held = paths
        .iter()
        .find(|p| !rooted(p) && (cwd.is_none() || climbs(p)));
    match held {
        Some(path) if cwd.is_none() => {
            let reason = format!("{verb} `{path}`: {RELATIVE}");
            Action::unchecked(action, reason)
        }
        Some(path) => {
            let reason = relative_escapes(path, verb);
            Action::unchecked(action, reason)
        }
        None => action,
    }
}

/// `patch` replaces text in `path`, or with `mode: patch` applies a V4A
/// multi-file patch (the `*** Begin Patch` envelope Codex's `apply_patch`
/// uses), which writes every file it adds, updates, deletes or moves to.
fn patch(args: &Value) -> Result<Action, HostError> {
    let field = |name: &'static str| crate::input_str(args, "patch", name);
    let mode = args.get("mode").and_then(Value::as_str).unwrap_or("replace");
    Ok(match mode {
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
    })
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
    match pattern {
        Some(pattern) if files => crate::bounded(action, [pattern]),
        _ => action,
    }
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

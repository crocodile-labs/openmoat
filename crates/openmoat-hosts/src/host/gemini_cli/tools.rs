//! Which action a Gemini CLI tool call is, from its name and arguments.
//!
//! Tool names and argument keys: <https://geminicli.com/docs/reference/tools/>
//! ("Tool argument keys") and the tool schemas in `@google/gemini-cli` 0.65.0
//! (`packages/core/src/tools/definitions`).

use openmoat_core::Action;
use serde_json::Value;

use super::McpContext;
use crate::{Host, HostError};

/// What one call is, and what the request records besides its action.
pub(super) struct Mapped {
    /// The action, or `None` for a tool OpenMoat does not govern.
    pub action: Option<Action>,
    /// The name to record when it is not Gemini CLI's (`mcp__<server>__<tool>`).
    pub tool: Option<String>,
    /// The directory a shell command runs in when it names one (`dir_path`).
    pub cwd: Option<String>,
}

impl Mapped {
    fn action(action: Action) -> Self {
        Self {
            action: Some(action),
            tool: None,
            cwd: None,
        }
    }
}

/// Tools that change only Gemini CLI's own state or talk to the person, and
/// the subagent tools, whose own tool calls go through the same hook
/// (`scheduleAgentTools` in `packages/core/src/agents/agent-scheduler.ts` runs
/// them through the scheduler that fires `BeforeTool`). `list_mcp_resources` only lists what connected servers offer.
const UNGOVERNED: &[&str] = &[
    "ask_user",
    "write_todos",
    "update_topic",
    "enter_plan_mode",
    "exit_plan_mode",
    "complete_task",
    "activate_skill",
    "get_internal_docs",
    "list_mcp_resources",
    "tracker_create_task",
    "tracker_update_task",
    "tracker_get_task",
    "tracker_list_tasks",
    "tracker_add_dependency",
    "tracker_visualize",
    "invoke_agent",
    "codebase_investigator",
    "generalist",
    "cli_help",
    "browser_agent",
];

/// Gemini CLI runs `run_shell_command` with PowerShell on Windows and bash
/// elsewhere (`getShellConfiguration` in `packages/core/src/utils/shell-utils.ts`);
/// the guard runs on the same machine.
pub(super) const POWERSHELL: bool = cfg!(windows);

pub(super) fn map(
    tool: &str,
    input: &Value,
    mcp: Option<&McpContext>,
    cwd: Option<&str>,
) -> Result<Mapped, HostError> {
    map_on(tool, input, mcp, cwd, POWERSHELL)
}

pub(super) fn map_on(
    tool: &str,
    input: &Value,
    mcp: Option<&McpContext>,
    cwd: Option<&str>,
    powershell: bool,
) -> Result<Mapped, HostError> {
    let field = |name: &'static str| crate::input_str(input, tool, name);
    if let Some(mcp) = mcp {
        let name = format!("mcp__{}__{}", mcp.server_name, mcp.tool_name);
        let action = crate::wire::mcp::action(&name, input)?;
        return Ok(Mapped {
            action: Some(action),
            tool: Some(name),
            cwd: None,
        });
    }
    let action = match tool {
        "run_shell_command" => {
            let command = field("command")?;
            let action = if powershell {
                Action::ForeignShell {
                    shell: "PowerShell".to_owned(),
                    command,
                }
            } else {
                Action::Shell { command }
            };
            return Ok(Mapped {
                action: Some(action),
                tool: None,
                cwd: dir_path(input, cwd),
            });
        }
        "read_file" => Action::FsRead {
            path: field("file_path")?,
        },
        "write_file" | "replace" => Action::FsWrite {
            path: field("file_path")?,
        },
        "list_directory" => Action::FsRead {
            path: field("dir_path")?,
        },
        "glob" => glob(input, cwd),
        // `search_file_content` is the legacy name of `grep_search`.
        "grep_search" | "search_file_content" => search_root(input, cwd),
        "read_many_files" => read_many(tool, input, cwd)?,
        "web_fetch" => fetch(tool, &field("prompt")?)?,
        "google_web_search" => Action::WebSearch {
            query: field("query")?,
        },
        "read_mcp_resource" => mcp_resource(tool, &field("uri")?)?,
        name if UNGOVERNED.contains(&name) => {
            return Ok(Mapped {
                action: None,
                tool: None,
                cwd: None,
            });
        }
        // A custom subagent, a discovered tool or an MCP tool Gemini CLI sent
        // no context for: what it touches is unknown.
        _ => Action::UnknownTool {
            host: Host::GeminiCli.id().to_owned(),
            tool: tool.to_owned(),
        },
    };
    Ok(Mapped::action(action))
}

/// `dir_path` when set, else the working directory; relative to the latter.
fn dir_path(input: &Value, cwd: Option<&str>) -> Option<String> {
    let dir = input
        .get("dir_path")
        .and_then(Value::as_str)
        .filter(|d| !d.is_empty())?;
    if !is_relative(dir) {
        return Some(dir.to_owned());
    }
    cwd.map(|cwd| format!("{}/{dir}", cwd.trim_end_matches(['/', '\\'])))
}

fn is_relative(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !(drive || path.starts_with(['/', '\\', '~']))
}

/// The directory a search reads: `dir_path`, else the working directory.
fn search_dir(input: &Value, cwd: Option<&str>) -> String {
    dir_path(input, cwd)
        .or_else(|| cwd.map(str::to_owned))
        .unwrap_or_else(|| ".".to_owned())
}

fn search_root(input: &Value, cwd: Option<&str>) -> Action {
    Action::FsRead {
        path: search_dir(input, cwd),
    }
}

/// `glob` searches `dir_path` for `pattern`. The pattern's own directory is
/// read too: an absolute one names it outright, and a relative one may climb
/// out of the searched directory (`../..`).
fn glob(input: &Value, cwd: Option<&str>) -> Action {
    let root = search_dir(input, cwd);
    let pattern = input
        .get("pattern")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty());
    let from_pattern = pattern
        .map(|p| static_part(p, None))
        .filter(|dir| dir != ".");
    // A `..` after a wildcard climbs too (`*/../..`).
    let climbed = pattern.and_then(|p| crate::glob_reach(&root, p));
    let mut paths = vec![root.clone()];
    match from_pattern {
        Some(dir) if !is_relative(&dir) => paths.push(dir),
        Some(dir) => paths.push(crate::below(&root, &dir)),
        None => {}
    }
    if let Some(climbed) = climbed
        && !paths.contains(&climbed)
    {
        paths.push(climbed);
    }
    match paths.len() {
        1 => Action::FsRead { path: root },
        _ => Action::ReadFiles { paths },
    }
}

/// `read_many_files` reads every path or glob in `include`, relative to the
/// working directory: a glob as the directory before its first wildcard.
fn read_many(tool: &str, input: &Value, cwd: Option<&str>) -> Result<Action, HostError> {
    let malformed = |problem: &str| HostError::MalformedArguments {
        tool: tool.to_owned(),
        problem: problem.to_owned(),
    };
    let list = match input.get("include") {
        Some(Value::Array(list)) if !list.is_empty() => list,
        _ => return Err(malformed("`include` is not a list of paths")),
    };
    let mut paths = Vec::with_capacity(list.len());
    for item in list {
        let pattern = item
            .as_str()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| malformed("`include` holds a value that is not a path"))?;
        paths.push(static_part(pattern, cwd));
        // A `..` after a wildcard climbs out of the working directory too.
        paths.extend(crate::glob_reach(cwd.unwrap_or("."), pattern));
    }
    Ok(Action::ReadFiles { paths })
}

/// The part of `pattern` before its first wildcard, cut back to a whole
/// directory; the working directory when nothing is left.
fn static_part(pattern: &str, cwd: Option<&str>) -> String {
    let Some(wild) = pattern.find(['*', '?', '[', '{']) else {
        return pattern.to_owned();
    };
    match pattern[..wild].rfind(['/', '\\']) {
        Some(0) => "/".to_owned(),
        Some(end) => pattern[..end].to_owned(),
        None => cwd.unwrap_or(".").to_owned(),
    }
}

/// `web_fetch` fetches every whitespace-separated word of `prompt` that holds
/// `://` (`parsePrompt` in `packages/core/src/tools/web-fetch.ts`). One URL is a
/// fetch. One action names one URL, so a prompt with several is refused with
/// how to go on, rather than leaving all but one unchecked.
fn fetch(tool: &str, prompt: &str) -> Result<Action, HostError> {
    let urls: Vec<&str> = prompt
        .split_whitespace()
        .filter(|w| w.contains("://"))
        .collect();
    let problem = match urls.as_slice() {
        [url] => {
            return Ok(Action::Fetch {
                url: github_raw(url),
            });
        }
        [] => "`prompt` names no URL".to_owned(),
        several => format!(
            "`prompt` names {} URLs and OpenMoat checks one per call; fetch each URL in a \
             call of its own",
            several.len()
        ),
    };
    Err(HostError::MalformedArguments {
        tool: tool.to_owned(),
        problem,
    })
}

/// Gemini CLI fetches a `github.com/<owner>/<repo>/blob/…` page from
/// `raw.githubusercontent.com` instead (`convertGithubUrlToRaw`).
fn github_raw(url: &str) -> String {
    let Some(rest) = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
    else {
        return url.to_owned();
    };
    let mut parts = rest.splitn(4, '/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(owner), Some(repo), Some("blob"), Some(path)) => {
            format!("https://raw.githubusercontent.com/{owner}/{repo}/{path}")
        }
        _ => url.to_owned(),
    }
}

/// `read_mcp_resource` names only a `uri`, which a connected server resolves:
/// a `file:` URI is read as the file it names; any other is an unknown tool,
/// since the server that answers is not named.
fn mcp_resource(tool: &str, uri: &str) -> Result<Action, HostError> {
    if let Some(path) = openmoat_core::file_url_path(uri) {
        return Ok(Action::FsRead { path });
    }
    if uri
        .get(..5)
        .is_some_and(|s| s.eq_ignore_ascii_case("file:"))
    {
        return Err(HostError::MalformedArguments {
            tool: tool.to_owned(),
            problem: format!("`{uri}` is a file URI without an absolute path"),
        });
    }
    Ok(Action::UnknownTool {
        host: Host::GeminiCli.id().to_owned(),
        tool: tool.to_owned(),
    })
}

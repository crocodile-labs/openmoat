//! OpenCode 1's tools mapped to actions. Tool ids and arguments are those of
//! OpenCode 1.19.4 (`packages/opencode/src/tool/*.ts`, `tool/registry.ts`,
//! `session/tools.ts`). The hook sees every tool, so a tool not named here is
//! decided as an MCP tool of the name it has, with every path, URL and command
//! its arguments name checked ([`crate::wire::unknown::mcp`]): the payload does
//! not tell an MCP server's tool from a plugin's apart by its name alone, and
//! OpenCode runs a call OpenMoat makes no decision on.

use openmoat_core::Action;
use serde_json::Value;

use super::Call;
use super::mcp::spelling;
use crate::HostError;

/// Tools that touch no file, command or network of this machine themselves:
/// `task` starts a subagent, whose calls are hooks of their own (with the
/// subagent's session id); `todowrite` keeps the session's to-do list;
/// `skill` loads a skill's instructions; `question` asks the person; `invalid`
/// answers a call the model got wrong; the resource lists only list what MCP
/// servers offer.
const UNGOVERNED: &[&str] = &[
    "task",
    "todowrite",
    "skill",
    "question",
    "invalid",
    "list_mcp_resources",
    "list_mcp_resource_templates",
];

/// Why a call of OpenCode's shell on Windows is left to OpenCode: it runs Git
/// Bash, PowerShell or `cmd` under the one tool id `bash`, and the payload
/// does not say which (`tool/shell/id.ts`).
const WINDOWS_SHELL: &str = "OpenCode's shell on Windows";

pub(super) fn map(call: &Call<'_>) -> Result<Option<Action>, HostError> {
    let tool = call.tool;
    let field = |name: &'static str| crate::input_str(call.args, tool, name);
    let action = match tool {
        "bash" if call.windows => Action::ForeignShell {
            shell: WINDOWS_SHELL.to_owned(),
            command: field("command")?,
        },
        "bash" => Action::Shell {
            command: in_dir(call, field("command")?)?,
        },
        // `lsp` (experimental) opens `filePath` and asks its language server about it.
        "read" | "lsp" => Action::FsRead {
            path: path(call, &field("filePath")?)?,
        },
        // `write` replaces the file; `edit` replaces text in it.
        "write" | "edit" => Action::FsWrite {
            path: path(call, &field("filePath")?)?,
        },
        // Offered to GPT models in place of `edit` and `write`.
        "apply_patch" => Action::Patch {
            writes: openmoat_core::patch_writes(&field("patchText")?)
                .iter()
                .map(|hunk| path(call, hunk))
                .collect::<Result<_, _>>()?,
        },
        // `glob` matches `pattern` below `path`, `grep` searches the files
        // there that `include` matches; an absolute pattern names its own
        // directory, and a `..` in one may climb out of `path`.
        "glob" => search(call, Some(&field("pattern")?))?,
        "grep" => search(call, optional(call, "include")?.as_deref())?,
        // `webfetch` only GETs `url` (ADR-017).
        "webfetch" => Action::Fetch { url: field("url")? },
        "websearch" => Action::WebSearch {
            query: field("query")?,
        },
        "read_mcp_resource" => crate::wire::mcp::read_resource(tool, call.args)?,
        // Code Mode's script runs in a confined interpreter; each MCP tool it
        // calls is a hook of its own (`tool/code-mode.ts`, `invokeChildTool`).
        "execute" => return Ok(None),
        name if UNGOVERNED.contains(&name) => return Ok(None),
        name => match mcp_name(name, call.mcp_servers) {
            Some(mcp) => crate::wire::mcp::action(&mcp, call.args)?,
            None => crate::wire::unknown::mcp(name, call.args)?,
        },
    };
    Ok(Some(action))
}

/// `command` as it runs in `workdir`, when the call names one: after a `cd`
/// there, so relative paths in it resolve where OpenCode runs it while the
/// project stays the session's. OpenCode resolves `workdir` against the
/// instance directory with `path.resolve` (`tool/shell.ts`), which expands no
/// `~`, so the path is quoted whole.
fn in_dir(call: &Call<'_>, command: String) -> Result<String, HostError> {
    Ok(match optional(call, "workdir")? {
        Some(dir) => format!("cd '{}' && {command}", dir.replace('\'', r"'\''")),
        None => command,
    })
}

/// What a search tool reads: `path` (else the instance directory), and where
/// `pattern` reaches beyond it.
fn search(call: &Call<'_>, pattern: Option<&str>) -> Result<Action, HostError> {
    let root = match optional(call, "path")? {
        Some(p) => path(call, &p)?,
        None => call.cwd.map(str::to_owned).ok_or_else(|| {
            malformed(
                call,
                "no `path` and the payload names no instance directory (`directory`)".to_owned(),
            )
        })?,
    };
    let mut paths = vec![root.clone()];
    if let Some(pattern) = pattern {
        paths.extend(crate::pattern_dir(pattern));
        paths.extend(crate::glob_reach(&root, pattern));
    }
    paths.dedup();
    let action = match paths.len() {
        1 => Action::FsRead { path: root },
        _ => Action::ReadFiles { paths },
    };
    Ok(crate::bounded(action, pattern))
}

/// An optional string argument: `None` when absent, `null` or empty, an
/// error when it is anything else.
fn optional(call: &Call<'_>, name: &str) -> Result<Option<String>, HostError> {
    match call.args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(malformed(call, format!("`{name}` is not a string"))),
    }
}

/// `raw` as OpenCode's tools open it: an absolute path as it is, anything else
/// joined to the instance directory (`path.join` or `path.resolve`), a leading
/// `~` included, which OpenCode does not expand. A relative path with no
/// directory in the payload is an adapter error.
fn path(call: &Call<'_>, raw: &str) -> Result<String, HostError> {
    if is_absolute(raw, call.windows) {
        return Ok(raw.to_owned());
    }
    match call.cwd {
        Some(dir) => Ok(crate::below(dir, raw)),
        None => Err(malformed(
            call,
            format!("`{raw}` is relative and the payload names no instance directory (`directory`)"),
        )),
    }
}

/// Node's `path.isAbsolute` on the platform OpenCode runs on.
fn is_absolute(path: &str, windows: bool) -> bool {
    if windows {
        let bytes = path.as_bytes();
        let drive = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\');
        drive || path.starts_with(['/', '\\'])
    } else {
        path.starts_with('/')
    }
}

/// `tool` as `mcp__<server>__<tool>` when its name begins with a configured
/// server's, spelled as OpenCode spells it (`<server>_<tool>`). When several
/// servers' spellings begin it, the longest wins, as OpenCode's own Code Mode
/// splits the name (`tool/code-mode.ts`, `groupByServer`); the pins of every
/// such server still apply to it (`mcp::Joined`).
fn mcp_name(tool: &str, servers: &[String]) -> Option<String> {
    servers
        .iter()
        .filter_map(|server| {
            let rest = tool.strip_prefix(&format!("{}_", spelling(server)))?;
            (!rest.is_empty()).then(|| (spelling(server).len(), server, rest))

        })
        .max_by_key(|(len, _, _)| *len)
        .map(|(_, server, rest)| format!("mcp__{server}__{rest}"))
}

fn malformed(call: &Call<'_>, problem: String) -> HostError {
    HostError::MalformedArguments {
        tool: call.tool.to_owned(),
        problem,
    }
}

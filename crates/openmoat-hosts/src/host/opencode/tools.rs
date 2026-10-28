//! OpenCode's tools mapped to actions: what the two plugin APIs share, and
//! each version's names and arguments (`tools/v1.rs`, `tools/v2.rs`). The
//! hook sees every tool, so a tool a version's list does not name is decided
//! as an MCP tool of the name it has, with every path, URL and command its
//! arguments name checked ([`crate::wire::unknown::mcp`]): the payload does
//! not tell an MCP server's tool from a plugin's by its name alone, and
//! OpenCode runs a call OpenMoat makes no decision on.

use openmoat_core::Action;
use serde_json::Value;

use super::mcp::spelling;
use super::{Api, Call};
use crate::HostError;

mod v1;
mod v2;

/// Why a call of OpenCode's shell on Windows is left to OpenCode: it runs Git
/// Bash, PowerShell or `cmd` under one tool id (`bash` in OpenCode 1, `shell`
/// in OpenCode 2), and the payload does not say which (1.x
/// `tool/shell/id.ts`; 2.x `core/src/shell/select.ts`).
const WINDOWS_SHELL: &str = "OpenCode's shell on Windows";

pub(super) fn map(call: &Call<'_>) -> Result<Option<Action>, HostError> {
    match call.api {
        Api::V1 => v1::map(call),
        Api::V2 => v2::map(call),
    }
}

/// A tool neither version's list names: an MCP tool of a configured server,
/// else any other tool, checked by what its arguments name.
fn other(call: &Call<'_>) -> Result<Action, HostError> {
    match mcp_name(call.tool, call.mcp_servers) {
        Some(mcp) => crate::wire::mcp::action(&mcp, call.args),
        None => crate::wire::unknown::mcp(call.tool, call.args),
    }
}

/// The shell tool: `command`, after a `cd` to `workdir` when the call names
/// one; on Windows left to OpenCode.
fn shell(call: &Call<'_>) -> Result<Action, HostError> {
    let command = crate::input_str(call.args, call.tool, "command")?;
    if call.windows {
        // A `workdir` that is not a string is malformed on every platform.
        optional(call, "workdir")?;
        return Ok(Action::ForeignShell {
            shell: WINDOWS_SHELL.to_owned(),
            command,
        });
    }
    Ok(Action::Shell {
        command: in_dir(call, command)?,
    })
}

/// `command` as it runs in `workdir`, when the call names one: after a `cd`
/// there, so relative paths in it resolve where OpenCode runs it while the
/// project stays the session's. OpenCode 1 resolves `workdir` with
/// `path.resolve`, which expands no `~`, so the path is quoted whole;
/// OpenCode 2 expands a leading `~` or `~/` (`FileAccess.resolvePath`), so
/// that is left outside the quotes.
fn in_dir(call: &Call<'_>, command: String) -> Result<String, HostError> {
    let Some(dir) = optional(call, "workdir")? else {
        return Ok(command);
    };
    let quote = |s: &str| format!("'{}'", s.replace('\'', r"'\''"));
    let target = match (call.api, home_relative(call, &dir)) {
        (Api::V2, Some("")) => "~".to_owned(),
        (Api::V2, Some(rest)) => format!("~/{}", quote(rest)),
        _ => quote(&dir),
    };
    Ok(format!("cd {target} && {command}"))
}

/// What a search tool reads: `path` (else the instance directory), and where
/// `pattern` reaches beyond it.
fn search(call: &Call<'_>, root: Option<String>, pattern: Option<&str>) -> Result<Action, HostError> {
    let root = match root {
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

/// `raw` as OpenCode's tools open it: an absolute path as it is; in
/// OpenCode 2 a leading `~` or `~/` (`~\` on Windows) as the home directory,
/// written `~/…` for the policy to expand; anything else joined to the
/// instance directory, which in OpenCode 1 includes a leading `~`. A relative
/// path with no directory in the payload is an adapter error.
fn path(call: &Call<'_>, raw: &str) -> Result<String, HostError> {
    if is_absolute(raw, call.windows) {
        return Ok(raw.to_owned());
    }
    if call.api == Api::V2
        && let Some(rest) = home_relative(call, raw)
    {
        return Ok(if rest.is_empty() {
            "~".to_owned()
        } else {
            format!("~/{rest}")
        });
    }
    match call.cwd {
        Some(dir) => Ok(crate::below(dir, raw)),
        None => Err(malformed(
            call,
            format!("`{raw}` is relative and the payload names no instance directory (`directory`)"),
        )),
    }
}

/// The rest of `raw` after a `~` OpenCode 2 expands: `~` alone (`Some("")`),
/// `~/`, and on Windows `~\`.
fn home_relative<'r>(call: &Call<'_>, raw: &'r str) -> Option<&'r str> {
    if raw == "~" {
        return Some("");
    }
    raw.strip_prefix("~/")
        .or_else(|| raw.strip_prefix("~\\").filter(|_| call.windows))
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
/// splits the name (1.x `tool/code-mode.ts`, `groupByServer`); the pins of
/// every such server still apply to it (`mcp::Joined`).
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

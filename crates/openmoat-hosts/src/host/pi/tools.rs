//! pi's tools mapped to actions. Tool names and inputs are those of pi 1.3.0
//! (`dist/core/tools/*.d.ts`; `docs/settings.md`, "defaultTools"; `docs/mcp.md`).
//! The extension sees every tool, so a tool not named here is an
//! `UnknownTool`: `defaults.tool.unknown` decides it.

use openmoat_core::Action;
use serde_json::Value;

use super::Call;
use crate::HostError;

/// Tools that touch no file, command or network of this machine themselves.
/// `codemode` runs the model's script in a `QuickJS` sandbox with no file
/// system or network (`docs/codemode.md`); each tool the script calls is a
/// `tool_call` of its own, checked on its own. `tool_search` only turns tools
/// on; the resource lists only list what MCP servers offer.
const UNGOVERNED: &[&str] = &[
    "codemode",
    "tool_search",
    "list_mcp_resources",
    "list_mcp_resource_templates",
];

/// Spaces pi turns into a plain space in a path (`dist/utils/paths.js`,
/// `UNICODE_SPACES`).
const UNICODE_SPACES: &[char] = &[
    '\u{00A0}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}',
    '\u{2007}', '\u{2008}', '\u{2009}', '\u{200A}', '\u{202F}', '\u{205F}', '\u{3000}',
];

pub(super) fn map(call: &Call<'_>) -> Result<Option<Action>, HostError> {
    let tool = call.tool;
    let field = |name: &'static str| crate::input_str(call.input, tool, name);
    let action = match tool {
        // pi's `bash` runs `command` in bash, Git Bash on Windows.
        "bash" => Action::Shell {
            command: field("command")?,
        },
        "powershell" => Action::ForeignShell {
            shell: "PowerShell".to_owned(),
            command: field("command")?,
        },
        "read" => Action::FsRead {
            path: path(call, &field("path")?)?,
        },
        // `write` replaces the file; `edit` replaces text in it.
        "write" | "edit" => Action::FsWrite {
            path: path(call, &field("path")?)?,
        },
        // Each searches `path`, else the working directory.
        "grep" | "ls" => Action::FsRead { path: root(call)? },
        // `find` matches `pattern` below `path`; an absolute pattern names its
        // own directory, which is read too.
        "find" => {
            let root = root(call)?;
            match crate::pattern_dir(&field("pattern")?) {
                Some(dir) if dir != root => Action::ReadFiles {
                    paths: vec![root, dir],
                },
                _ => Action::FsRead { path: root },
            }
        }
        "read_mcp_resource" => crate::wire::mcp::read_resource(tool, call.input)?,
        name if UNGOVERNED.contains(&name) => return Ok(None),
        // `mcp__<server>__<tool>` (`docs/mcp.md`, "Tools").
        name if name.starts_with("mcp__") => crate::wire::mcp::action(name, call.input)?,
        _ => Action::UnknownTool {
            host: crate::Host::Pi.id().to_owned(),
            tool: tool.to_owned(),
        },
    };
    Ok(Some(action))
}

/// The directory a search tool reads: its `path`, else (none, or empty, which
/// pi reads as `.`) the working directory.
fn root(call: &Call<'_>) -> Result<String, HostError> {
    match call.input.get("path") {
        Some(Value::String(p)) if !p.is_empty() => return path(call, p),
        None | Some(Value::Null | Value::String(_)) => {}
        Some(_) => return Err(malformed(call, "`path` is not a path".to_owned())),
    }
    call.cwd.map(str::to_owned).ok_or_else(|| {
        malformed(
            call,
            "no `path` and the payload names no working directory (`cwd`)".to_owned(),
        )
    })
}

/// `raw` as pi's tools resolve it (`resolveToCwd` in `dist/core/tools/path-utils.js`):
/// Unicode spaces become spaces, a leading `@` goes, on Windows a Git Bash,
/// MSYS or WSL drive path (`/c/x`, `/mnt/c/x`, `/cygdrive/c/x`) becomes `C:/x`,
/// and a `file:` URL is the path it names. `~` and a relative path are left to
/// the guard, which resolves them against the home and `cwd`.
fn path(call: &Call<'_>, raw: &str) -> Result<String, HostError> {
    let spaced = raw.replace(UNICODE_SPACES, " ");
    let mut path = spaced.strip_prefix('@').unwrap_or(&spaced).to_owned();
    if call.windows
        && let Some(native) = windows_drive(&path)
    {
        path = native;
    }
    if path
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("file://"))
    {
        let named = openmoat_core::file_url_path(&path)
            .ok_or_else(|| malformed(call, format!("`{raw}` is not a file URL with a path")))?;
        // `file:///C:/x` names `C:/x` on Windows.
        path = match named.strip_prefix('/') {
            Some(rest) if call.windows && is_drive(rest) => rest.to_owned(),
            _ => named,
        };
    }
    if is_relative(&path) && call.cwd.is_none() {
        return Err(malformed(
            call,
            format!("`{raw}` is relative and the payload names no working directory (`cwd`)"),
        ));
    }
    Ok(path)
}

/// `/c/x`, `/mnt/c/x` or `/cygdrive/c/x` as `C:/x`; `None` for any other path.
fn windows_drive(path: &str) -> Option<String> {
    if path.starts_with("//") || path.contains('\\') {
        return None;
    }
    let rest = path.strip_prefix('/')?;
    let rest = rest
        .strip_prefix("mnt/")
        .or_else(|| rest.strip_prefix("cygdrive/"))
        .unwrap_or(rest);
    let mut chars = rest.chars();
    let drive = chars.next().filter(char::is_ascii_alphabetic)?;
    let tail = chars.as_str();
    if !(tail.is_empty() || tail.starts_with('/')) {
        return None;
    }
    let tail = tail.strip_prefix('/').unwrap_or(tail);
    Some(format!("{}:/{tail}", drive.to_ascii_uppercase()))
}

fn is_drive(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_relative(path: &str) -> bool {
    !(is_drive(path) || path.starts_with(['/', '\\', '~']))
}

fn malformed(call: &Call<'_>, problem: String) -> HostError {
    HostError::MalformedArguments {
        tool: call.tool.to_owned(),
        problem,
    }
}

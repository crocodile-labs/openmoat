//! OpenCode 2's tools. Tool names and arguments are those of OpenCode 2.2.0
//! (`packages/core/src/tool/plugin/*.ts`, `core/src/codemode/tool.ts`,
//! `core/src/tool/runtime.ts`): paths are `path`, resolved against the
//! instance directory with a leading `~` expanded (`core/src/file-access.ts`,
//! `resolvePath`).

use openmoat_core::Action;

use super::{Call, optional, other, path, search, shell};
use crate::HostError;

/// Tools that touch no file, command or network of this machine themselves:
/// `subagent` starts one, whose calls are hooks of their own; `todowrite`,
/// `question` and `skill` keep the to-do list, ask the person and load a
/// skill's instructions; `list_mcp_resources` lists what MCP servers offer;
/// Code Mode's `execute` runs a script whose every tool call is a hook of its
/// own (`core/src/tool.ts`, `CodeModeTool.create`); and of OpenCode's own
/// tools (namespace `opencode`), renaming a session, listing worktrees and
/// searching the models.
const UNGOVERNED: &[&str] = &[
    "subagent",
    "todowrite",
    "question",
    "skill",
    "list_mcp_resources",
    "execute",
    "opencode_session_rename",
    "opencode_worktree_list",
    "opencode_models",
];

pub(super) fn map(call: &Call<'_>) -> Result<Option<Action>, HostError> {
    let tool = call.tool;
    let field = |name: &'static str| crate::input_str(call.args, tool, name);
    let action = match tool {
        "shell" => shell(call)?,
        "read" => Action::FsRead {
            path: path(call, &field("path")?)?,
        },
        // `write` replaces the file; `edit` replaces text in it.
        "write" | "edit" => Action::FsWrite {
            path: path(call, &field("path")?)?,
        },
        "patch" => Action::Patch {
            writes: openmoat_core::patch_writes(&field("patchText")?)
                .iter()
                .map(|hunk| path(call, hunk))
                .collect::<Result<_, _>>()?,
        },
        // `glob` matches `pattern` below `path` (whose text `undefined` or
        // `null` OpenCode reads as none), `grep` searches the files there
        // that `include` matches.
        "glob" => {
            let root = optional(call, "path")?.filter(|p| p != "undefined" && p != "null");
            search(call, root, Some(&field("pattern")?))?
        }
        "grep" => search(
            call,
            optional(call, "path")?,
            optional(call, "include")?.as_deref(),
        )?,
        // `webfetch` only GETs `url` (ADR-017).
        "webfetch" => Action::Fetch { url: field("url")? },
        "websearch" => Action::WebSearch {
            query: field("query")?,
        },
        "read_mcp_resource" => crate::wire::mcp::read_resource(tool, call.args)?,
        // Deletes the worktree at `directory`, which OpenCode asks about as
        // an edit (`core/src/tool/plugin/opencode.ts`).
        "opencode_worktree_remove" => Action::FsWrite {
            path: path(call, &field("directory")?)?,
        },
        name if UNGOVERNED.contains(&name) => return Ok(None),
        _ => other(call)?,
    };
    Ok(Some(action))
}

//! OpenCode 1's tools. Tool ids and arguments are those of OpenCode 1.19.4
//! (`packages/opencode/src/tool/*.ts`, `tool/registry.ts`, `session/tools.ts`).

use openmoat_core::Action;

use super::{Call, optional, other, path, search, shell};
use crate::HostError;

/// Tools that touch no file, command or network of this machine themselves:
/// `task` starts a subagent, whose calls are hooks of their own (with the
/// subagent's session id); `todowrite` keeps the session's to-do list;
/// `skill` loads a skill's instructions; `question` asks the person; `invalid`
/// answers a call the model got wrong; the resource lists only list what MCP
/// servers offer; Code Mode's `execute` script runs in a confined
/// interpreter, and each MCP tool it calls is a hook of its own
/// (`tool/code-mode.ts`, `invokeChildTool`).
const UNGOVERNED: &[&str] = &[
    "task",
    "todowrite",
    "skill",
    "question",
    "invalid",
    "execute",
    "list_mcp_resources",
    "list_mcp_resource_templates",
];

pub(super) fn map(call: &Call<'_>) -> Result<Option<Action>, HostError> {
    let tool = call.tool;
    let field = |name: &'static str| crate::input_str(call.args, tool, name);
    let action = match tool {
        "bash" => shell(call)?,
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
        "glob" => search(call, optional(call, "path")?, Some(&field("pattern")?))?,
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
        name if UNGOVERNED.contains(&name) => return Ok(None),
        _ => other(call)?,
    };
    Ok(Some(action))
}

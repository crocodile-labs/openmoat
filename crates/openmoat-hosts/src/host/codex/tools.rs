//! Codex's own tools beyond the shared `PreToolUse` mapping, and the shell
//! calls whose later input no hook sees.
//!
//! Codex 0.166 names its local tools by their function name
//! (`core/src/tools/handlers/mod.rs`): `read_mcp_resource {server, uri}` reads
//! a resource from an MCP server (`mcp_resource_spec.rs`) and `view_image
//! {path}` puts a local image file into the conversation (`view_image_spec.rs`).

use openmoat_core::Action;
use serde_json::Value;

use crate::HostError;

mod stdin;

#[cfg(test)]
mod tests;

/// The action of one of Codex's own tools; `None` for a tool the shared
/// mapping reads.
pub(super) fn own(tool: &str, input: &Value) -> Option<Result<Action, HostError>> {
    match tool {
        "read_mcp_resource" => Some(crate::wire::mcp::read_resource(tool, input)),
        "view_image" => Some(view_image(input)),
        _ => None,
    }
}

/// `view_image` reads the image at `path`. A URL there is fetched, a `file:`
/// URL read as the file it names, so either is checked rather than taken for
/// a relative path.
fn view_image(input: &Value) -> Result<Action, HostError> {
    let path = crate::input_str(input, "view_image", "path")?;
    let scheme = path.chars().take(8).collect::<String>().to_ascii_lowercase();
    if scheme.starts_with("http://") || scheme.starts_with("https://") {
        return Ok(Action::Fetch { url: path });
    }
    if let Some(file) = openmoat_core::file_url_path(&path) {
        return Ok(Action::FsRead { path: file });
    }
    if scheme.starts_with("file:") {
        return Err(HostError::MalformedArguments {
            tool: "view_image".to_owned(),
            problem: format!("`{path}` is a file URI without an absolute path"),
        });
    }
    Ok(Action::FsRead { path })
}

/// `action`, needing review when it starts a program that reads its commands
/// from its input: Codex's `write_stdin` then types into it with no hook, so
/// what it runs is never seen ([`stdin::reads_commands`]).
pub(super) fn held(action: Action) -> Action {
    let program = match &action {
        Action::Shell { command } => stdin::reads_commands(command),
        _ => None,
    };
    match program {
        Some(program) => Action::unchecked(
            action,
            format!(
                "Codex types later input into `{program}` with `write_stdin`, which runs no \
                 hook, so what it runs is not checked; give it the commands to run instead \
                 (a script file, `-c` or `-e`)"
            ),
        ),
        None => action,
    }
}

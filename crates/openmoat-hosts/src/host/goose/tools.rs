//! goose tools: which action a `PreToolUse` call is, from the tool's name and
//! its arguments.
//!
//! goose sends the name the model sees. The built-in `developer`, `analyze`,
//! `summon`, `code_execution` and `skills` extensions are not prefixed;
//! every other extension's tools are `<extension>__<tool>`, the extension's
//! key with every character but ASCII letters, digits, `_` and `-` as `_`,
//! lowercased (`name_to_key` in `config/extensions.rs`; `fetch_public_tools`
//! in `agents/extension_manager/mod.rs`). The argument shapes are each tool's
//! own (v1.57.0): `developer/{shell,edit,tree,image}.rs`, `analyze/mod.rs`,
//! `summon.rs`, `code_execution.rs`, `skills/client.rs`.

use openmoat_core::Action;
use serde_json::Value;

use crate::{Host, HostError};

/// Whether goose's shell is `cmd` (or `GOOSE_SHELL`): on Windows
/// (`windows_shell` in `developer/shell.rs`).
pub(super) const WINDOWS_SHELL: bool = cfg!(windows);

/// Tools that only read goose's own catalogue of tools.
const CATALOGUE: &[&str] = &["list_functions", "get_function_details"];

/// Why a Code Mode script is held: the tools it calls run without the hook
/// (`dispatch_tool` in `code_execution.rs` calls the extension directly).
const CODE_MODE: &str = "Code Mode runs the tools a script calls without goose's hook, so \
     OpenMoat sees none of them";

/// The action of a call, and the tool name to record when it is not goose's.
pub(super) struct Mapped {
    /// The action, or `None` for a tool OpenMoat does not govern.
    pub action: Option<Action>,
    /// The name to record when it is not goose's (`mcp__<extension>__<tool>`).
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

/// The action of the `tool` call with arguments `input` (an object).
pub(super) fn map(tool: &str, input: &Value) -> Result<Mapped, HostError> {
    map_on(tool, input, WINDOWS_SHELL)
}

/// [`map`] with goose's shell named: `cmd` when `windows`.
pub(super) fn map_on(tool: &str, input: &Value, windows: bool) -> Result<Mapped, HostError> {
    let field = |name: &'static str| crate::input_str(input, tool, name);
    let action = match tool {
        "shell" if windows => Action::ForeignShell {
            shell: "cmd (or GOOSE_SHELL)".to_owned(),
            command: field("command")?,
        },
        "shell" => Action::Shell {
            command: field("command")?,
        },
        "write" | "edit" => Action::FsWrite {
            path: field("path")?,
        },
        // `tree` lists a directory; `analyze` parses the files under a path.
        "tree" | "analyze" => Action::FsRead {
            path: field("path")?,
        },
        // A local path, or an http(s) URL goose downloads.
        "read_image" => {
            let source = field("source")?;
            let lower = source.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") {
                Action::Fetch { url: source }
            } else {
                Action::FsRead { path: source }
            }
        }
        "execute_javascript" => {
            Action::unchecked(crate::wire::unknown::action(Host::Goose, tool, input)?, CODE_MODE)
        }
        // `load` reads a recipe or subrecipe into the context, `delegate`
        // starts a subagent (whose calls fire the hook: it runs on the same
        // agent), `load_skill` a skill or one of its files: every path, URL
        // and command they name is checked.
        "load" | "delegate" | "load_skill" => crate::wire::unknown::action(Host::Goose, tool, input)?,
        name if CATALOGUE.contains(&name) => {
            return Ok(Mapped {
                action: None,
                tool: None,
            });
        }
        name => match name.split_once("__") {
            Some((extension, own)) if !extension.is_empty() && !own.is_empty() => {
                let recorded = format!("mcp__{extension}__{own}");
                let action = crate::wire::mcp::action(&recorded, input)?;
                return Ok(Mapped {
                    action: Some(action),
                    tool: Some(recorded),
                });
            }
            // A tool of an extension goose exposes unprefixed that this
            // adapter does not know yet.
            _ => crate::wire::unknown::action(Host::Goose, name, input)?,
        },
    };
    Ok(Mapped::action(action))
}

//! Claude Code's hook as another agent runs it (ADR-097).
//!
//! Some agents load the hooks of `~/.claude/settings.json` and a project's
//! `.claude/settings*.json` and run them with input of their own:
//!
//! - Grok Build (`grok`) sends its own envelope, camelCase (`hookEventName`
//!   `pre_tool_use`, `sessionId`, `toolName`, `toolInput`, `workspaceRoot`),
//!   with Claude Code's snake-case names added beside it (`hook_event_name`
//!   `PreToolUse`, `session_id`, `tool_name`, `tool_input`,
//!   `tool_response`). The tool keeps its Grok name (`run_terminal_command`,
//!   `search_replace`); only a matcher's Claude names are mapped onto Grok's
//!   (`xai-org/grok-build` at 2bdd1d6a, `crates/codegen/xai-grok-hooks/src/event.rs`
//!   `to_hook_json` and `matcher.rs` `claude_bash_matches_grok_tool`;
//!   discovery of `~/.claude/settings.json` in `discovery.rs`). Only an
//!   explicit deny blocks there: exit 2 or `{"decision": "deny"}`; anything
//!   else, `ask` included, runs the call (<https://docs.x.ai/build/features/hooks>).
//! - The Devin CLI loads `.claude/` hooks by default (`read_config_from.claude`)
//!   and sends its own tool names (`exec`, `read`, `edit`, `grep`, `webfetch`)
//!   in Claude Code's field names; it reads a top-level `decision`
//!   (`approve` or `block`) or exit 2, and runs the call on any other answer
//!   (<https://docs.devin.ai/cli/extensibility/hooks/overview>,
//!   <https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks>).
//!
//! Read with Claude Code's own mapping, such a call would name a tool that
//! mapping does not know and be left ungoverned, so the other agent would run
//! it unchecked, and a `review` sent as `ask` would run too. So a payload is
//! foreign when it carries Grok's envelope or names a tool OpenMoat's own
//! `PreToolUse` entry never asks Claude Code about ([`TOOL_MATCHER`]'s names).
//! Such a tool is read as an unknown tool ([`crate::wire::unknown`]): every
//! path, URL and command its arguments name is checked. The call is decided as
//! one that cannot prompt, so a `review` is a deny that says how to approve
//! it; a deny exits 2, which both agents read as a block; a `defer` gives no
//! answer and leaves the call to the agent, as it does for Claude Code. A
//! payload that is not a JSON object with a tool name is still an error,
//! which `guard` denies.
//!
//! [`TOOL_MATCHER`]: super::TOOL_MATCHER

use serde::Deserialize;
use serde_json::Value;

use crate::wire::pre_tool_use;
use crate::{HookEvent, HookRequest, Host, HostError};

/// The key of Grok Build's own envelope, which Claude Code never sends.
const GROK_ENVELOPE: &str = "hookEventName";

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    tool_name: Option<String>,
}

/// Whether `payload` was sent by another agent running Claude Code's hook:
/// Grok Build's envelope, or a tool `matcher` does not name.
pub(super) fn sent_by_another_agent(payload: &str, matcher: &str) -> bool {
    let Ok(Value::Object(top)) = serde_json::from_str::<Value>(payload) else {
        return false;
    };
    if top.contains_key(GROK_ENVELOPE) {
        return true;
    }
    serde_json::from_value::<Envelope>(Value::Object(top))
        .ok()
        .and_then(|e| e.tool_name)
        .is_some_and(|tool| !names(matcher, &tool))
}

/// Whether Claude Code may send `tool` to an entry with `matcher`, a
/// `|`-separated list of tool names in which an entry may end in `.*`. A
/// matcher with a character other than letters, digits, `_`, `-`, spaces,
/// `,` and `|` is an unanchored JavaScript regular expression, which matches
/// anywhere in the name (the hooks reference, "Matcher patterns"): OpenMoat's
/// `Write` also matches `TodoWrite`, which stays Claude Code's.
fn names(matcher: &str, tool: &str) -> bool {
    matcher.split('|').any(|entry| {
        let name = entry.strip_suffix(".*").unwrap_or(entry);
        !name.is_empty() && tool.contains(name)
    })
}

/// The request in a foreign payload ([`sent_by_another_agent`]) for the
/// `PreToolUse` or `PostToolUse` entry: a tool Claude Code's mapping knows is
/// read as Claude Code reads it, any other as an unknown tool.
pub(super) fn parse(
    host: Host,
    event: Option<&str>,
    payload: &str,
    matcher: &str,
) -> Result<HookRequest, HostError> {
    let unknown = |tool: &str, input: &Value, cwd: Option<&str>| {
        if names(matcher, tool) {
            super::ide_tools::action(tool, input, cwd)
        } else {
            Some(crate::wire::unknown::action(host, tool, input))
        }
    };
    match event {
        None | Some(pre_tool_use::EVENT) => {
            let mut request = pre_tool_use::parse_with(host, payload, unknown)?;
            request.event = HookEvent::PreToolUseNoPrompt;
            Ok(request)
        }
        Some(super::post_tool_use::EVENT) => {
            let request = pre_tool_use::parse_with(host, payload, unknown)?;
            super::post_tool_use::with_output(request, payload)
        }
        other => Err(crate::contract::wrong_event(other)),
    }
}

#[cfg(test)]
mod tests;

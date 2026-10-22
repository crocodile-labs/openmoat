//! The Continue CLI (`cn`) runs the Claude Code hooks.
//!
//! `cn` merges hooks from `~/.claude/settings.json` and `.claude/settings.json`
//! with its own files and pipes them the Claude Code `PreToolUse` document. Its
//! runner (`extensions/cli/src/hooks/hookRunner.ts`) blocks only on exit 2,
//! `decision: "block"` or `permissionDecision: "deny"`; an `ask` lets the call
//! run. So `guard` has to tell a `cn` call from a Claude Code one and answer
//! `cn`'s asks as denies ([`Host::answer`]).

use serde::Deserialize;

use crate::Host;
use crate::contract::{Asks, Detect, HostDocs, HostSpec};

/// `cn` sends Claude Code's hooks, ignores `ask` and runs the call.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "continue",
    display_name: "Continue CLI",
    speaks: Some(Host::ClaudeCode),
    asks: Asks {
        on_pre_tool_use: Some("the Continue CLI runs a call its hook asks about"),
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
        ..Asks::BASE
    },
    on_hook_failure: "runs the call when the hook is missing, cannot start, exits non-zero \
         other than 2, or times out (default 600 s)",
    gaps: "the released Continue CLI does not run hooks, so OpenMoat cannot check its tool \
         calls; run it under `openmoat run`",
    // `cn` reads its own configuration and fires no hook.
    mcp: None,
    // Its global directory (`CONTINUE_GLOBAL_DIR`, else `~/.continue`, as `cn`
    // resolves it), or `cn` on the search path.
    detect: Some(Detect {
        dir_variable: "CONTINUE_GLOBAL_DIR",
        dir_name: ".continue",
        binary: "cn",
    }),
    // Its tool calls are Claude Code's, mapped by Claude Code's rows.
    docs: HostDocs {
        hooked_by: "`cn` runs the Claude Code hook, but the released `cn` runs no hooks yet",
        protection: "not checked yet; use `openmoat run`",
        ..HostDocs::BASE
    },
    ..HostSpec::BASE
};

/// Set by `cn` for every command hook it runs, next to `CLAUDE_PROJECT_DIR`
/// (`executeCommandHook` in `hookRunner.ts`); Claude Code never sets it.
pub const CONTINUE_ENV: &str = "CONTINUE_PROJECT_DIR";

impl Host {
    /// The host that really sent `payload` to the hook installed for `self`;
    /// `continue_env` says whether [`CONTINUE_ENV`] is set for the hook.
    ///
    /// Only the Claude Code hook is shared. `cn` is recognised by
    /// [`CONTINUE_ENV`] or by the empty `transcript_path` it sends (it keeps no
    /// transcript file), where Claude Code always sends a path. Either signal is
    /// enough: a Claude Code call taken for `cn` has its ask turned into a deny,
    /// while a `cn` call taken for Claude Code would run on an ask.
    #[must_use]
    pub fn sender(self, payload: &str, continue_env: bool) -> Self {
        if self == Self::ClaudeCode && (continue_env || has_empty_transcript(payload)) {
            Self::Continue
        } else {
            self
        }
    }
}

fn has_empty_transcript(payload: &str) -> bool {
    #[derive(Deserialize)]
    struct Envelope {
        transcript_path: Option<String>,
    }
    serde_json::from_str::<Envelope>(payload)
        .is_ok_and(|e| e.transcript_path.is_some_and(|path| path.is_empty()))
}

#[cfg(test)]
mod tests {
    use openmoat_core::{Action, Decision, Verdict};

    use super::*;
    use crate::{HookEvent, HostError};

    fn fixture(path: &str) -> String {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/hosts");
        std::fs::read_to_string(format!("{root}/{path}")).unwrap()
    }

    #[test]
    fn cn_is_told_apart_from_claude_code() {
        let cn = fixture("continue/pretooluse-bash.json");
        let claude = fixture("claude-code/bash.json");
        assert_eq!(Host::ClaudeCode.sender(&cn, false), Host::Continue);
        assert_eq!(Host::ClaudeCode.sender(&claude, true), Host::Continue);
        assert_eq!(Host::ClaudeCode.sender(&claude, false), Host::ClaudeCode);
        assert_eq!(Host::ClaudeCode.sender("not json", false), Host::ClaudeCode);
        // Only the Claude Code hook is shared with `cn`.
        assert_eq!(Host::Codex.sender(&cn, true), Host::Codex);
        assert_eq!(Host::Cursor.sender(&cn, true), Host::Cursor);
    }

    #[test]
    fn cn_payloads_parse_as_claude_code_ones() {
        let req = Host::Continue
            .parse_request(&fixture("continue/pretooluse-bash.json"))
            .unwrap();
        assert_eq!(req.host, Host::Continue);
        assert_eq!(req.call_id.as_deref(), Some("call_k2Jd8sQx1Lw3"));
        assert_eq!(
            req.action,
            Some(Action::Shell {
                command: "git config core.pager less".into()
            })
        );
        // `cn` names the path of `Read` `filepath`, not `file_path`: refused, not
        // waved through.
        assert!(matches!(
            Host::Continue.parse_request(&fixture("continue/pretooluse-read.json")),
            Err(HostError::MissingField { .. })
        ));
    }

    #[test]
    fn cn_receives_an_ask_as_a_deny_that_says_how_to_approve() {
        let mut ask = Decision::new(Verdict::Ask);
        ask.rules.push("installs".into());
        let cn = Host::Continue.answer(&HookEvent::PreToolUse, &ask);
        assert_eq!(cn.verdict, Verdict::Deny);
        assert_eq!(cn.rules, ask.rules);
        assert!(crate::reason_line(&cn).contains("Continue CLI"));
        assert!(crate::reason_line(&cn).contains("openmoat allow --last"));
        let allow = Decision::new(Verdict::Allow);
        assert_eq!(Host::Continue.answer(&HookEvent::PreToolUse, &allow), allow);
    }

    #[test]
    fn continue_is_recorded_but_not_installable() {
        assert_eq!(Host::Continue.id(), "continue");
        assert!(!Host::ALL.contains(&Host::Continue));
        assert!("continue".parse::<Host>().is_err());
    }
}

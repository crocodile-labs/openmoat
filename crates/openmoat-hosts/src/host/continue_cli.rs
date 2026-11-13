//! The Continue CLI (`cn`) runs the Claude Code hooks.
//!
//! `cn` merges hooks from `~/.claude/settings.json` and `.claude/settings.json`
//! with its own files and pipes them the Claude Code `PreToolUse` document. Its
//! runner (`extensions/cli/src/hooks/hookRunner.ts`) blocks only on exit 2,
//! `decision: "block"` or `permissionDecision: "deny"`; `"ask"` (OpenMoat's
//! `review`) lets the call run. So `guard` has to tell a `cn` call from a
//! Claude Code one and answer
//! `cn`'s reviews as denies ([`Host::answer`]).

use serde::Deserialize;

use crate::Host;
use crate::contract::{Reviews, Detect, HostDocs, HostSpec};

/// `cn` sends Claude Code's hooks, ignores `"ask"` and runs the call.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "continue",
    display_name: "Continue CLI",
    speaks: Some(Host::ClaudeCode),
    speaks_variable: Some(CONTINUE_ENV),
    reviews: Reviews {
        on_pre_tool_use: Some("the Continue CLI runs a call its hook holds for review"),
        on_no_prompt: None,
        defer_is_review_on_no_prompt: false,
        ..Reviews::BASE
    },
    on_hook_failure: "runs the call when the hook is missing, cannot start, exits non-zero \
         other than 2, or times out (default 600 s)",
    // `cn` runs no hooks; its hook runner, were it called, lets a failure go.
    hook_failure: crate::HookFailure {
        fails: crate::FailureOutcome::Runs,
        times_out: crate::FailureOutcome::Runs,
        timeout_s: Some(600),
        turned_off_by: "always: the released Continue CLI fires no hook",
        sources: &[
            "https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/hookRunner.ts",
        ],
    },
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
    process: crate::contract::ProcessSpec {
        names: &["cn"],
        package_dirs: &[&["@continuedev", "cli"]],
        helper: None,
    },
    // `cn` is not set up by `moat init`, so `CONTINUE_GLOBAL_DIR` moving its
    // directory is not followed.
    protect: crate::contract::Protect {
        credentials: &[crate::contract::Paths::new(
            "Continue CLI: the hub login older releases kept (`src/auth/workos.ts`) and\n\
             the MCP sign-ins of `mcp-remote`, which `cn` starts for a remote server that\n\
             asks for one (`src/services/MCPService.ts`)",
            &["~/.continue/auth.json", "~/.mcp-auth/**"],
        )],
        taint: &[crate::contract::Paths::new(
            "Continue CLI: its configuration, whose MCP servers it starts",
            &["**/.continue/config.yaml"],
        )],
        runs_later: &[crate::contract::RunsLater::review(
            "Continue CLI: its configuration, whose `mcpServers` it starts",
            &["~/.continue/config.yaml"],
        )],
        ..crate::contract::Protect::BASE
    },
    // Its tool calls are Claude Code's, mapped by Claude Code's rows.
    docs: HostDocs {
        hooked_by: "`cn` runs the Claude Code hook, but the released `cn` runs no hooks yet",
        protection: "not checked yet; use `openmoat run`",
        ..HostDocs::BASE
    },
    // `$SHELL -l -c` for tools, `/bin/sh -c` for hooks (ADR-075).
    tool_token: crate::ToolToken::Wrapper {
        vars: &["SHELL"],
        on_path: false,
    },
    run: crate::RunFacts::Unknown {
        why: "which directories `cn` writes outside the project was not checked",
    },
    ..HostSpec::BASE
};

/// Set by `cn` for every command hook it runs, next to `CLAUDE_PROJECT_DIR`
/// (`executeCommandHook` in `hookRunner.ts`); Claude Code never sets it.
const CONTINUE_ENV: &str = "CONTINUE_PROJECT_DIR";

impl Host {
    /// The variable a host running another host's hook sets for it
    /// ([`HostSpec::speaks_variable`]), which the guard reads and passes to
    /// [`Self::sender`] and `openmoat run` forwards.
    #[must_use]
    pub fn caller_variable() -> Option<&'static str> {
        Self::EVERY.iter().find_map(|h| h.spec().speaks_variable)
    }

    /// The host that really sent `payload` to the hook installed for `self`;
    /// `caller_set` says whether [`Self::caller_variable`] is set for the hook.
    ///
    /// Only the Claude Code hook is shared. `cn` is recognised by
    /// `CONTINUE_ENV` or by the empty `transcript_path` it sends (it keeps no
    /// transcript file), where Claude Code always sends a path. Either signal is
    /// enough: a Claude Code call taken for `cn` has its review turned into a deny,
    /// while a `cn` call taken for Claude Code would run on a review.
    #[must_use]
    pub fn sender(self, payload: &str, caller_set: bool) -> Self {
        if self == Self::ClaudeCode && (caller_set || has_empty_transcript(payload)) {
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

    /// The payload `<id>/<file>` from the folder of the host with that id.
    fn fixture(path: &str) -> String {
        let (id, name) = path.split_once('/').unwrap();
        let host = Host::EVERY.into_iter().find(|h| h.id() == id).unwrap();
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src/host");
        std::fs::read_to_string(format!("{root}/{}/fixtures/{name}", host.module())).unwrap()
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
    fn cn_receives_a_review_as_a_deny_that_says_how_to_approve() {
        let mut review = Decision::new(Verdict::Review);
        review.rules.push("installs".into());
        let cn = Host::Continue.answer(&HookEvent::PreToolUse, &review);
        assert_eq!(cn.verdict, Verdict::Deny);
        assert_eq!(cn.rules, review.rules);
        assert!(crate::reason_line(&cn).contains("Continue CLI"));
        assert!(crate::reason_line(&cn).contains("openmoat allow --last"));
        let allow = Decision::new(Verdict::Allow);
        assert_eq!(Host::Continue.answer(&HookEvent::PreToolUse, &allow), allow);
    }

    /// The only host that runs another's hook names the one variable the
    /// guard reads and `openmoat run` forwards.
    #[test]
    fn the_variable_that_says_cn_runs_the_hook_comes_from_its_spec() {
        assert_eq!(Host::caller_variable(), Some("CONTINUE_PROJECT_DIR"));
        let specs = Host::EVERY
            .iter()
            .filter(|h| h.spec().speaks_variable.is_some());
        assert_eq!(specs.count(), 1);
    }

    #[test]
    fn continue_is_recorded_but_not_installable() {
        assert_eq!(Host::Continue.id(), "continue");
        assert!(!Host::ALL.contains(&Host::Continue));
        assert!("continue".parse::<Host>().is_err());
    }
}

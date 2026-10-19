//! The Codex CLI: `PreToolUse` in Claude Code's format
//! ([`crate::wire::pre_tool_use`]).

use openmoat_core::{Decision, Verdict};
use serde_json::json;

use crate::bench::{Answer, CONTENT, Call, Exit, Place};
use crate::contract::{Asks, HostAdapter, HostSpec, InstallSpec, wrong_event};
use crate::wire::pre_tool_use::{self, bench};
use crate::{HookEvent, HookRequest, Host, HostError};

/// Codex's `PreToolUse` rejects `permissionDecision: "ask"` as unsupported and
/// then runs the call.
pub(crate) static SPEC: HostSpec = HostSpec {
    id: "codex",
    display_name: "Codex",
    speaks: None,
    asks: Asks {
        on_pre_tool_use: Some("Codex hooks cannot ask"),
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
    },
    on_hook_failure: "runs the call when the hook is missing, cannot start, exits non-zero \
         other than 2 (or 2 with nothing on stderr), or times out (default 600 s)",
    gaps: "web search and hosted tools are not hooked; asks become denies; calls run \
         unchecked if the hook binary is missing or crashes",
    install: Some(InstallSpec {
        dir_variable: "CODEX_HOME",
        dir_name: ".codex",
        config_file: "hooks.json",
    }),
};

/// Codex sends only `PreToolUse`.
pub(crate) struct Adapter;

pub(crate) static ADAPTER: Adapter = Adapter;

impl HostAdapter for Adapter {
    fn spec(&self) -> &'static HostSpec {
        &SPEC
    }

    /// `PreToolUse` may come without its event name.
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError> {
        match event {
            None | Some(pre_tool_use::EVENT) => pre_tool_use::parse(host, payload),
            other => Err(wrong_event(other)),
        }
    }

    fn render(&self, _event: &HookEvent, decision: &Decision) -> String {
        pre_tool_use::render(decision)
    }

    /// Codex reads files through its shell and has no fetch tool; it writes
    /// and edits with `apply_patch`.
    fn bench_payload(&self, call: &Call, at: &Place<'_>) -> Option<String> {
        let apply = |body: String| ("apply_patch".to_owned(), json!({ "command": body }));
        let (tool, input) = match call {
            Call::Write(path) => apply(format!(
                "*** Begin Patch\n*** Add File: {}\n+{CONTENT}\n*** End Patch\n",
                at.file(path)
            )),
            Call::Edit(path) => apply(format!(
                "*** Begin Patch\n*** Update File: {}\n@@\n-old\n+{CONTENT}\n*** End Patch\n",
                at.file(path)
            )),
            other => bench::common_tool(other)?,
        };
        Some(bench::payload(&tool, &input, at))
    }

    /// Codex blocks on exit 2 only with a reason on stderr.
    fn read_reply(&self, _call: &Call, exit: &Exit<'_>) -> Answer {
        if exit.code == Some(2) && exit.stderr.trim().is_empty() {
            return Answer::Error;
        }
        bench::read_reply(exit, false)
    }

    /// Codex cannot ask, so an `ask` has to arrive as a blocking `deny`.
    fn seen(&self, _call: &Call, verdict: Verdict) -> Answer {
        match verdict {
            Verdict::Ask => Answer::Deny,
            other => other.into(),
        }
    }
}

//! Hook formats more than one host sends, and the argument reading they share.

use openmoat_core::Verdict;

pub(crate) mod guard_command;
pub(crate) mod hook_file;
pub(crate) mod mcp;
pub(crate) mod mcp_call;
pub(crate) mod owned_file;
pub(crate) mod pre_tool_use;
pub(crate) mod unknown;

/// The word a host's hook protocol reads for `verdict`. OpenMoat's `review`
/// is sent as the host's `"ask"` (ADR-053): Claude Code, Codex, Copilot CLI,
/// Cursor and Gemini CLI spell it so, and the plugins for OpenClaw, OpenCode
/// and pi, including those an older release installed, read `"ask"` from
/// `openmoat guard`. Every adapter renders the verdict through this function,
/// never through [`Verdict::as_str`], so OpenMoat's own name never reaches a host.
pub(crate) fn host_verdict(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Review => "ask",
        other => other.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use openmoat_core::Verdict;

    use super::host_verdict;

    #[test]
    fn review_is_the_hosts_ask_and_the_rest_keep_their_names() {
        assert_eq!(host_verdict(Verdict::Review), "ask");
        for (verdict, word) in [
            (Verdict::Allow, "allow"),
            (Verdict::Defer, "defer"),
            (Verdict::Deny, "deny"),
        ] {
            assert_eq!(host_verdict(verdict), word);
        }
    }
}

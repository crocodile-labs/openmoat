//! Cursor `beforeTabFileRead`: Tab, Cursor's inline completion, is about to
//! read a file (<https://cursor.com/docs/agent/hooks>, Tab hooks). The input
//! has `file_path` and `content`, the output only `permission`, `allow` or
//! `deny`; a response that does not match the hook's schema blocks the read.
//!
//! Tab is no agent and runs no tool: it reads the files the person edits to
//! complete what they type, and sends them to Cursor's model. Until this hook
//! it read every file unchecked. OpenMoat refuses what the default policy
//! never lets an agent read (secrets, other agents' logins) and lets every
//! other read through, a `defer` included: Tab has no question to put to the
//! person, and holding every file outside the project for review would stop
//! completions there for nothing. A `review` is a deny.

use openmoat_core::{Decision, Verdict};

/// The hook.
pub(super) const EVENT: &str = "beforeTabFileRead";

/// The tool a Tab read is recorded as.
pub(super) const TOOL: &str = "TabRead";

/// Only `permission`: the documented output, nothing else.
pub(super) fn render(decision: &Decision) -> String {
    // Any verdict but these two is held back: one added later blocks the read.
    let permission = match decision.verdict {
        Verdict::Allow | Verdict::Defer => "allow",
        _ => "deny",
    };
    format!(r#"{{"permission":"{permission}"}}"#)
}

#[cfg(test)]
mod tests {
    use openmoat_core::Action;

    use super::*;
    use crate::{HookEvent, Host};

    const FIXTURE: &str = include_str!("fixtures/beforeTabFileRead.json");

    #[test]
    fn a_tab_read_is_a_read_of_its_file() {
        let req = Host::Cursor.parse_request(FIXTURE).unwrap();
        assert_eq!(req.tool, TOOL);
        assert_eq!(
            req.action,
            Some(Action::FsRead {
                path: "/p/.env".into()
            })
        );
        assert_eq!(req.event, HookEvent::PreToolUse);
        let missing = r#"{"hook_event_name":"beforeTabFileRead","workspace_roots":["/p"]}"#;
        assert!(Host::Cursor.parse_request(missing).is_err());
    }

    /// A `defer` reaches Tab as `allow`, a `review` as `deny`, and the answer
    /// carries nothing but `permission`.
    #[test]
    fn tab_gets_allow_or_deny_only() {
        let req = Host::Cursor.parse_request(FIXTURE).unwrap();
        for (verdict, permission) in [
            (Verdict::Allow, "allow"),
            (Verdict::Defer, "allow"),
            (Verdict::Review, "deny"),
            (Verdict::Deny, "deny"),
        ] {
            let decided = Host::Cursor.decided(&req.event, Decision::new(verdict));
            assert_eq!(decided.verdict, verdict, "{verdict:?} is recorded as decided");
            let answer = Host::Cursor.answer(&req.event, &decided);
            assert_eq!(
                Host::Cursor.render_response_for(&req, &answer),
                format!(r#"{{"permission":"{permission}"}}"#),
                "{verdict:?}"
            );
        }
    }
}

//! Claude Code `SessionStart` hook: a session starts, resumes, or begins again
//! after `/clear` or a compaction (ADR-044).
//!
//! OpenMoat uses it to give the session's sandboxed commands their own
//! credential for `openmoat proxy`: the hook can append `export` lines to the
//! file `CLAUDE_ENV_FILE` names, which Claude Code runs before each later Bash
//! command of that session (the hooks reference, "Persist environment
//! variables"). Nothing is decided: the event has no tool call, and Claude Code
//! cannot block a session from starting. Its stdout would be added to the
//! model's context, so the response is always empty; a failure exits 2, whose
//! stderr Claude Code shows the person.
//!
//! Claude Code sends `source` (`startup`, `resume`, `clear`, `compact`).

use openmoat_core::Decision;
use serde::Deserialize;

use crate::{HookEvent, HookRequest, Host, HostError};

pub(crate) const EVENT: &str = "SessionStart";

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id),
        call_id: None,
        cwd: p.cwd,
        tool: EVENT.to_owned(),
        action: None,
        content: None,
        mcp_arguments: None,
        event: HookEvent::SessionStart {
            source: p.source.unwrap_or_default(),
        },
    })
}

/// Always empty: Claude Code adds a `SessionStart` hook's stdout to the
/// model's context, and nothing here is for the model. A failure is reported
/// on stderr with exit 2.
pub(crate) fn render(_decision: &Decision) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use openmoat_core::Verdict;

    use super::*;

    fn fixture() -> String {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/host/claude_code/fixtures"
        );
        std::fs::read_to_string(format!("{dir}/session-start.json")).unwrap()
    }

    #[test]
    fn parses_the_session_and_its_source_and_names_no_action() {
        let req = Host::ClaudeCode.parse_request(&fixture()).unwrap();
        assert_eq!(req.session_id, "7c1e4b2a-55d0-4b8e-9a51-0e3c2f7d9b10");
        assert_eq!(req.cwd.as_deref(), Some("/p"));
        assert_eq!(req.tool, EVENT);
        assert_eq!(req.action, None);
        assert_eq!(
            req.event,
            HookEvent::SessionStart {
                source: "startup".into()
            }
        );
        assert_eq!(
            Host::ClaudeCode.event_of(&fixture()),
            HookEvent::SessionStart {
                source: String::new()
            }
        );
    }

    #[test]
    fn the_response_is_always_empty() {
        for verdict in [Verdict::Allow, Verdict::Deny] {
            let event = HookEvent::SessionStart {
                source: "startup".into(),
            };
            assert_eq!(
                Host::ClaudeCode.render_response(&event, &Decision::new(verdict)),
                ""
            );
        }
    }

    #[test]
    fn a_malformed_payload_is_an_error() {
        let bad = r#"{"hook_event_name": "SessionStart", "session_id": 7}"#;
        assert!(Host::ClaudeCode.parse_request(bad).is_err());
    }
}

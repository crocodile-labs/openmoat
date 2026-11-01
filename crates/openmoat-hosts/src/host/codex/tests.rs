use openmoat_core::{Decision, Verdict};
use serde_json::Value;

use crate::{HookEvent, Host};

#[test]
fn an_allow_is_no_output_and_every_stop_is_a_deny_with_a_reason() {
    let event = HookEvent::PreToolUse;
    // Codex reports a bare `permissionDecision: "allow"` as an unsupported reply
    // and a failed hook; no output is its "no objection".
    for verdict in [Verdict::Allow, Verdict::Defer] {
        let answer = Host::Codex.answer(&event, &Decision::new(verdict));
        assert_eq!(Host::Codex.render_response(&event, &answer), "", "{verdict:?}");
    }
    // Codex cannot ask, and a deny needs a non-empty reason.
    for verdict in [Verdict::Ask, Verdict::Deny] {
        let answer = Host::Codex.answer(&event, &Decision::new(verdict));
        let doc: Value =
            serde_json::from_str(&Host::Codex.render_response(&event, &answer)).unwrap();
        let out = &doc["hookSpecificOutput"];
        assert_eq!(out["permissionDecision"], "deny", "{verdict:?}");
        assert!(!out["permissionDecisionReason"].as_str().unwrap().trim().is_empty());
    }
}

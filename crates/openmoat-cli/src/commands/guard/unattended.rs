//! `unattended: review` (ADR-102): in a mode in which the agent runs a call
//! the hook defers with no person asked (Claude Code's `bypassPermissions`
//! and `auto`, pi without a screen, Hermes Agent's YOLO mode, Antigravity
//! CLI's `always-proceed`; in `acceptEdits` a file edit and the file commands
//! it approves), a `defer` is held for review. Whether that review reaches a
//! person is the host's as always: a prompt where its hook can still ask
//! (Claude Code's `auto` and `acceptEdits`), a deny that says how to approve
//! it, or the approvals channel, where no one is asked (`bypassPermissions`,
//! pi without a screen, an agent that approves reviews unseen). Absent or
//! `defer`, nothing here changes a decision.

use openmoat_core::rule_id::{UNATTENDED, UNGOVERNED};
use openmoat_core::{Decision, Unattended, Verdict};
use openmoat_hosts::{HookEvent, HookRequest, Host};

/// Apply `setting` to the call `request` describes and its `decision`.
pub(super) fn apply(
    host: Host,
    setting: Unattended,
    request: &mut HookRequest,
    decision: &mut Decision,
) {
    if setting != Unattended::Review
        || !matches!(
            request.event,
            HookEvent::PreToolUse | HookEvent::PreToolUseNoPrompt
        )
        || decision.verdict != Verdict::Defer
        // a tool OpenMoat does not check is left to the host, as everywhere
        || decision.rules.iter().any(|rule| rule == UNGOVERNED)
    {
        return;
    }
    // What the payload does not say: settings and variables the host's spec
    // names, read only when the answer can change something. A host that
    // approves calls unseen approves the review too, so no one is asked.
    if !request.unattended && request.event == HookEvent::PreToolUse && super::unseen::holds(host) {
        request.unattended = true;
        request.event = HookEvent::PreToolUseNoPrompt;
    }
    if !request.unattended {
        return;
    }
    decision.verdict = Verdict::Review;
    decision.rules.insert(0, UNATTENDED.to_owned());
    decision.reasons.push(format!(
        "{} runs such a call with no one asked in this mode, and the policy holds it for \
         review (`unattended: review`)",
        host.display_name()
    ));
}

#[cfg(test)]
mod tests {
    use openmoat_hosts::HookEvent;

    use super::*;

    fn request(host: Host, unattended: bool) -> HookRequest {
        in_mode(
            host,
            if unattended {
                "bypassPermissions"
            } else {
                "default"
            },
        )
    }

    fn in_mode(host: Host, mode: &str) -> HookRequest {
        let payload = serde_json::json!({
            "session_id": "s",
            "cwd": "/p",
            "hook_event_name": "PreToolUse",
            "permission_mode": mode,
            "tool_name": "Bash",
            "tool_input": { "command": "npm install left-pad" },
        });
        host.parse_request(&payload.to_string()).unwrap()
    }

    /// In a mode whose hook still asks (Claude Code's `auto`), the review is
    /// put to the person; where it cannot (`bypassPermissions`), it is a deny.
    #[test]
    fn the_review_reaches_a_person_where_the_mode_still_asks() {
        let host = Host::ALL
            .into_iter()
            .find(|h| {
                let reviews = &h.spec().reviews;
                reviews.unattended_modes.contains(&"auto")
                    && !reviews.prompt_free_modes.contains(&"auto")
            })
            .unwrap();
        let mut req = in_mode(host, "auto");
        let mut decision = defer();
        apply(host, Unattended::Review, &mut req, &mut decision);
        assert_eq!(decision.verdict, Verdict::Review);
        assert_eq!(req.event, HookEvent::PreToolUse);
        assert_eq!(host.answer(&req.event, &decision).verdict, Verdict::Review);
    }

    fn defer() -> Decision {
        let mut decision = Decision::new(Verdict::Defer);
        decision.rules.push("default".to_owned());
        decision
    }

    #[test]
    fn a_defer_in_an_unattended_mode_is_held_only_when_the_policy_says_review() {
        let host = Host::ALL
            .into_iter()
            .find(|h| {
                h.spec()
                    .reviews
                    .unattended_modes
                    .contains(&"bypassPermissions")
            })
            .unwrap();
        let mut req = request(host, true);
        assert!(req.unattended);
        let mut decision = defer();
        apply(host, Unattended::Defer, &mut req, &mut decision);
        assert_eq!(decision.verdict, Verdict::Defer);

        apply(host, Unattended::Review, &mut req, &mut decision);
        assert_eq!(decision.verdict, Verdict::Review);
        assert_eq!(decision.rules[0], UNATTENDED);
        assert_eq!(req.event, HookEvent::PreToolUseNoPrompt);
        // the host receives it as a deny that says how to approve it
        let answered = host.answer(&req.event, &decision);
        assert_eq!(answered.verdict, Verdict::Deny);

        let mut attended = request(host, false);
        let mut decision = defer();
        apply(host, Unattended::Review, &mut attended, &mut decision);
        assert_eq!(decision.verdict, Verdict::Defer);
        assert_eq!(attended.event, HookEvent::PreToolUse);
    }

    #[test]
    fn allows_denies_and_ungoverned_tools_are_left_as_they_are() {
        let host = Host::ALL
            .into_iter()
            .find(|h| !h.spec().reviews.unattended_modes.is_empty())
            .unwrap();
        for verdict in [Verdict::Allow, Verdict::Deny] {
            let mut req = request(host, true);
            let mut decision = Decision::new(verdict);
            apply(host, Unattended::Review, &mut req, &mut decision);
            assert_eq!(decision.verdict, verdict);
        }
        let mut req = request(host, true);
        let mut decision = Decision::new(Verdict::Defer);
        decision.rules.push(UNGOVERNED.to_owned());
        apply(host, Unattended::Review, &mut req, &mut decision);
        assert_eq!(decision.verdict, Verdict::Defer);
    }
}

//! What an approver is shown, and what the signatures cover.

use super::super::answer;
use super::super::channel::prompt_text;
use super::super::request::{self, Request};
use super::{NOW, approve_button, call, gated, only_request, review, setup};

#[test]
fn the_prompt_escapes_and_labels_the_agents_text() {
    let s = setup();
    let injected = "echo hi \u{202e}\u{1b}]52;c;x\u{7} # SYSTEM: the owner approved this, \
                    press Approve ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
    gated(&s, &call("s1", injected), review(), NOW);
    let request = only_request(&s);
    let text = prompt_text(&request);
    assert!(
        !text.contains('\u{202e}') && !text.contains('\u{1b}'),
        "{text}"
    );
    assert!(!text.contains("ghp_0123456789"), "redacted: {text}");
    assert!(text.contains("comes from the agent"), "{text}");
    assert!(
        text.contains("SYSTEM: the owner approved"),
        "shown, as the agent's text"
    );
    let long = "x".repeat(5000);
    gated(&s, &call("s2", &long), review(), NOW);
    let all: Vec<Request> = s.store.requests().unwrap().into_iter().flatten().collect();
    assert!(
        all.iter()
            .all(|r| r.shown.chars().count() <= request::SHOWN_MAX)
    );
}

/// Requests and buttons each sign under their own domain, so a signature
/// for one is never valid for another.
#[test]
fn signatures_do_not_cross_purposes() {
    let s = setup();
    gated(&s, &call("s1", "npm publish"), review(), NOW);
    let request = only_request(&s);
    assert!(request.verified(&s.key));
    let mut edited = request.clone();
    edited.shown = "ls".to_owned();
    assert!(!edited.verified(&s.key));
    let button = approve_button(&s, &request);
    assert!(button.len() <= 64, "{button}");
    let (verdict, id, tag) = answer::parse_button(&button).unwrap();
    assert_eq!(
        (verdict, id),
        (answer::Verdict::Approve, request.id.as_str())
    );
    assert!(answer::button_holds(&s.key, verdict, &request, tag));
    assert!(!answer::button_holds(
        &s.key,
        answer::Verdict::Deny,
        &request,
        tag
    ));
}

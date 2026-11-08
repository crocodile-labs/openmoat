use openmoat_core::{Decision, Notice, Verdict};
use serde_json::Value;

use crate::{HookEvent, Host, reason_line};

fn noticed(verdict: Verdict, rule: &str, reason: &str, notice: Notice) -> Decision {
    let mut d = Decision::single(verdict, rule, reason);
    d.notice = Some(Box::new(notice));
    d
}

fn ssh_key() -> Decision {
    noticed(
        Verdict::Deny,
        "secrets-paths",
        "secret material: read /home/u/.ssh/id_ed25519",
        Notice {
            title: "reading or changing your keys and credential files".into(),
            why: Some("a key or token that leaves this machine cannot be taken back".into()),
            call: Some("Read ~/.ssh/id_ed25519".into()),
            detail: Some("secret material: read ~/.ssh/id_ed25519".into()),
            ..Notice::default()
        },
    )
}

fn push_hook() -> Decision {
    noticed(
        Verdict::Review,
        "runs-later",
        "CI, commit hooks, the editor or the agent host run this later: write .git/hooks/pre-push",
        Notice {
            title: "changing something that runs later, outside any sandbox".into(),
            why: None,
            call: Some("Write .git/hooks/pre-push".into()),
            ..Notice::default()
        },
    )
}

/// One of OpenMoat's own checks, with a step of its own.
fn drifted() -> Decision {
    noticed(
        Verdict::Deny,
        "kernel-integrity",
        "~/.moat/policy.yaml was modified",
        Notice {
            title: "any call while OpenMoat's own files differ from their pins".into(),
            next: Some("run `openmoat doctor` in your terminal to see what changed".into()),
            ..Notice::default()
        },
    )
}

/// A check's own step replaces the verdict's; where the host cannot ask, how
/// to approve still comes first.
#[test]
fn a_checks_own_next_step_replaces_the_verdicts() {
    let text = reason_line(&drifted());
    assert!(
        text.contains("\n  next   run `openmoat doctor` in your terminal to see what changed\n"),
        "{text}"
    );
    let mut held = push_hook();
    if let Some(notice) = held.notice.as_mut() {
        notice.next = Some("approve it in this prompt only if you asked for it yourself".into());
    }
    assert!(
        reason_line(&held).contains("\n  next   approve it in this prompt only if you asked"),
        "{}",
        reason_line(&held)
    );
    let codex = Host::Codex.answer(&HookEvent::PreToolUse, &held);
    assert!(
        reason_line(&codex).contains("\n  next   Codex hooks cannot prompt, so approve it"),
        "{}",
        reason_line(&codex)
    );
}

#[test]
fn a_deny_reads_as_six_lines_headed_by_the_rule_title() {
    assert_eq!(
        reason_line(&ssh_key()),
        "OpenMoat blocked: reading or changing your keys and credential files\n\
         \x20 call   Read ~/.ssh/id_ed25519\n\
         \x20 rule   moat: deny [secrets-paths] — secret material: read ~/.ssh/id_ed25519\n\
         \x20 why    a key or token that leaves this machine cannot be taken back\n\
         \x20 next   if you need this, do it yourself in your own terminal\n\
         \x20 more   openmoat why --last · https://openmoat.dev/r/secrets-paths"
    );
}

#[test]
fn a_review_says_it_is_held_and_how_to_answer_it() {
    assert_eq!(
        reason_line(&push_hook()),
        "OpenMoat is holding this for you: changing something that runs later, outside any sandbox\n\
         \x20 call   Write .git/hooks/pre-push\n\
         \x20 rule   moat: review [runs-later] — CI, commit hooks, the editor or the agent host run \
         this later: write .git/hooks/pre-push\n\
         \x20 next   approve it in this prompt only if you expected it\n\
         \x20 more   openmoat why --last"
    );
}

/// Codex cannot prompt: the review reaches it as a deny whose `next` line says
/// how the person approves it, and the reasons gain nothing.
#[test]
fn a_review_a_host_cannot_ask_about_says_how_to_approve_it() {
    let answer = Host::Codex.answer(&HookEvent::PreToolUse, &push_hook());
    assert_eq!(answer.verdict, Verdict::Deny);
    assert_eq!(answer.reasons, push_hook().reasons);
    let text = reason_line(&answer);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "OpenMoat is holding this for you: changing something that runs later, outside any sandbox"
    );
    assert!(
        lines[2].starts_with("  rule   moat: deny [runs-later] — "),
        "{text}"
    );
    assert_eq!(
        lines[3],
        "  next   Codex hooks cannot prompt, so approve it in your terminal: run `openmoat`, or \
         `openmoat allow --last`, then retry"
    );
    assert_eq!(lines[4], "  more   openmoat why --last");
}

/// Without a notice (a rule with no title, a check with no words), and for an
/// allow or a defer, the line is exactly what earlier releases sent.
#[test]
fn without_a_notice_the_line_is_unchanged() {
    let plain = Decision::single(Verdict::Deny, "kernel-integrity", "the lock drifted");
    assert_eq!(
        reason_line(&plain),
        "moat: deny [kernel-integrity] — the lock drifted"
    );
    let held = Host::Codex.answer(
        &HookEvent::PreToolUse,
        &Decision::single(Verdict::Review, "runs-later", "r"),
    );
    assert!(
        reason_line(&held).starts_with("moat: deny [runs-later] — r; this needs your approval")
    );
    for verdict in [Verdict::Allow, Verdict::Defer] {
        let mut d = ssh_key();
        d.verdict = verdict;
        let line = reason_line(&d);
        assert!(line.starts_with(&format!("moat: {} [secrets-paths]", verdict.as_str())));
        assert!(!line.contains('\n'), "{line}");
    }
}

/// A pack's or repository's rule has no page on the site.
#[test]
fn only_a_plain_rule_id_gets_a_page_link() {
    let mut d = ssh_key();
    d.rules = vec!["pack:team:keys".into()];
    assert!(reason_line(&d).ends_with("  more   openmoat why --last"));
}

/// The block reaches the model: one `next` step, at most six lines, no
/// colour, and no wording that points the agent at another way to the same end.
#[test]
fn the_block_is_short_plain_and_never_suggests_a_way_around() {
    let codex = Host::Codex.answer(&HookEvent::PreToolUse, &push_hook());
    for d in [ssh_key(), push_hook(), codex, drifted()] {
        let text = reason_line(&d);
        assert!(text.lines().count() <= 6, "{text}");
        assert_eq!(text.matches("\n  next ").count(), 1, "{text}");
        assert!(!text.contains('\x1b'), "{text}");
        let lower = text.to_lowercase();
        for hint in crate::NEVER_SUGGESTED {
            assert!(!lower.contains(hint), "`{hint}` in {text}");
        }
    }
}

/// Every string a response holds, wherever the host's format puts it.
fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| strings(v, out)),
        _ => {}
    }
}

/// Every host's response carries the whole block in its reason field, as
/// JSON (so the line breaks are escaped), for a deny and for a review.
#[test]
fn every_host_carries_the_block_in_its_reason_field() {
    for host in Host::EVERY {
        for decision in [ssh_key(), push_hook()] {
            let event = HookEvent::PreToolUse;
            let answer = host.answer(&event, &host.decided(&event, decision));
            let response = host.render_response(&event, &answer);
            let doc: Value = serde_json::from_str(&response)
                .unwrap_or_else(|e| panic!("{host:?}: {e}: {response}"));
            let mut found = Vec::new();
            strings(&doc, &mut found);
            let block = reason_line(&answer);
            assert!(found.contains(&block), "{host:?}: {response}");
            assert!(block.starts_with("OpenMoat "), "{host:?}: {block}");
            assert!(!response.contains('\x1b'), "{host:?}");
        }
    }
}

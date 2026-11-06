use openmoat_audit::KnownSecrets;
use openmoat_core::{Action, Decision, Policy, Verdict};

use super::{Titles, call_text, middle, of};

const POLICY: &str = "version: 1\n\
    deny:\n  - id: keys\n    reason: secret material\n    title: reading your SSH keys\n    \
    why: a key that leaves cannot be taken back\n    fs.read: ['~/.ssh/**']\n\
    review:\n  - id: push\n    shell: ['git push']\n";

fn read(path: &str) -> Action {
    Action::FsRead { path: path.into() }
}

#[test]
fn a_titled_deny_gets_a_notice_with_the_call_and_its_rule_text() {
    let policy = Policy::parse(POLICY).unwrap();
    let d = Decision::single(Verdict::Deny, "keys", "secret material: read ~/.ssh/id");
    let action = read("~/.ssh/id");
    let notice = of(
        &d,
        &Titles::of(&policy, &d),
        Some(("Read", Some(&action))),
        &KnownSecrets::default(),
    )
    .unwrap();
    assert_eq!(notice.title, "reading your SSH keys");
    assert_eq!(
        notice.why.as_deref(),
        Some("a key that leaves cannot be taken back")
    );
    assert_eq!(notice.call.as_deref(), Some("Read ~/.ssh/id"));
    assert_eq!(
        notice.detail.as_deref(),
        Some("secret material: read ~/.ssh/id")
    );
}

/// Each reason is shortened on its own: with two rules, the second reason's
/// source (what tainted the session) stays on the `rule` line.
#[test]
fn every_reason_keeps_its_own_text() {
    let policy = Policy::parse(POLICY).unwrap();
    let path = format!("/tmp/{}/home/proj/.github/workflows/ci.yml", "x".repeat(40));
    let mut d = Decision::single(Verdict::Deny, "keys", format!("runs later: write {path}"));
    d.rules.push("taint".into());
    d.reasons.push(format!(
        "the session read untrusted content (ran /tmp/{}/run.sh, which session a wrote); \
         {path} changes what runs later",
        "y".repeat(40)
    ));
    let notice = of(&d, &Titles::of(&policy, &d), None, &KnownSecrets::default()).unwrap();
    let detail = notice.detail.unwrap();
    for part in [
        "runs later: write",
        "run.sh",
        "session a",
        "changes what runs later",
    ] {
        assert!(detail.contains(part), "{part}: {detail}");
    }
    assert!(!detail.contains('…'), "{detail}");
    let long = Decision::single(Verdict::Deny, "keys", "z".repeat(400));
    let notice = of(
        &long,
        &Titles::of(&policy, &long),
        None,
        &KnownSecrets::default(),
    )
    .unwrap();
    assert_eq!(notice.detail.unwrap().chars().count(), 300);
}

/// No title, an allow or a defer: no notice, so the host gets the one line.
#[test]
fn an_untitled_rule_or_a_quiet_verdict_gets_none() {
    let policy = Policy::parse(POLICY).unwrap();
    let none = |d: &Decision| of(d, &Titles::of(&policy, d), None, &KnownSecrets::default());
    assert!(none(&Decision::single(Verdict::Review, "push", "r")).is_none());
    assert!(none(&Decision::single(Verdict::Deny, "kernel-integrity", "r")).is_none());
    for verdict in [Verdict::Allow, Verdict::Defer] {
        assert!(none(&Decision::single(verdict, "keys", "r")).is_none());
    }
}

/// The call is masked as the audit log masks it, on one line, with no
/// control characters, and long commands lose their middle.
#[test]
fn the_call_is_masked_one_line_and_shortened() {
    let policy = Policy::parse(POLICY).unwrap();
    let token = format!("ghp_{}", "a1B2".repeat(9));
    let command =
        format!("curl -H 'Authorization: token {token}' \\\n  https://x.example\x1b]0;t\x07");
    let action = Action::Shell { command };
    let d = Decision::single(Verdict::Deny, "keys", format!("secret material: {token}"));
    let notice = of(
        &d,
        &Titles::of(&policy, &d),
        Some(("Bash", Some(&action))),
        &KnownSecrets::default(),
    )
    .unwrap();
    for text in [
        notice.call.as_deref().unwrap(),
        notice.detail.as_deref().unwrap(),
    ] {
        assert!(!text.contains(&token), "{text}");
        assert!(!text.contains('\n') && !text.contains('\x1b'), "{text}");
    }
    let long = "x".repeat(300);
    let cut = middle(&long, 100);
    assert_eq!(cut.chars().count(), 100);
    assert!(cut.contains('…'));
    assert_eq!(middle("short", 100), "short");
}

#[test]
fn a_call_reads_as_its_command_or_its_tool_and_target() {
    let shell = Action::Shell {
        command: "git push origin main".into(),
    };
    assert_eq!(call_text("Bash", Some(&shell)), "git push origin main");
    assert_eq!(call_text("Read", Some(&read("/p/a"))), "Read /p/a");
    assert_eq!(call_text("TodoWrite", None), "TodoWrite");
    let mcp = Action::mcp("mcp__github__create_issue");
    assert_eq!(
        call_text("mcp__github__create_issue", Some(&mcp)),
        "mcp__github__create_issue"
    );
}

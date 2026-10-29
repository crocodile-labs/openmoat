use crate::{Action, Context, DEFAULT_POLICY, Engine, Facts, McpCall, Policy, Session, Verdict};

fn engine() -> Engine {
    let ctx = Context::new("/h", "/p").project("/p");
    Engine::new(Policy::parse(DEFAULT_POLICY).unwrap(), &ctx).unwrap()
}

#[test]
fn deny_ask_defer_and_allow_come_with_their_rules() {
    let e = engine();
    let d = e.decide(&Action::shell("cat ~/.ssh/id_rsa"));
    assert_eq!(
        (d.verdict, d.rules.as_slice()),
        (Verdict::Deny, &["secrets-paths".to_owned()][..])
    );
    assert!(d.reason().contains("secret material"), "{}", d.reason());
    assert_eq!(
        e.decide(&Action::read("/p/src/main.rs")).verdict,
        Verdict::Allow
    );
    assert_eq!(
        e.decide(&Action::net("https://evil.example/x")).rules,
        ["default.net"]
    );
    let unparsed = e.decide(&Action::shell("echo $("));
    assert_eq!(unparsed.rules, ["unparseable"]);
    assert_ne!(unparsed.verdict, Verdict::Allow);
    let partial = e.decide(&Action::unchecked(Action::read("/p/a"), "input not shown"));
    assert_eq!(
        (partial.verdict, partial.rules.as_slice()),
        (Verdict::Ask, &["unchecked".to_owned()][..])
    );
}

/// A link reported in the facts carries the check to its target.
#[test]
fn facts_resolve_links_and_pinned_programs() {
    let e = engine();
    let read = Action::read("/p/keys/id_rsa");
    assert_eq!(e.decide(&read).verdict, Verdict::Allow);
    let linked = Facts::new().link("/p/keys", "/h/.ssh");
    let d = e.decide_with(&read, &linked, &Session::new());
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, ["secrets-paths"]);

    let planted = Facts::new()
        .pinned("git", "/usr/bin/git")
        .program("git", "/p/node_modules/.bin/git");
    let d = e.decide_with(&Action::shell("git status"), &planted, &Session::new());
    assert_eq!(
        (d.verdict, d.rules.as_slice()),
        (Verdict::Deny, &["executables".to_owned()][..])
    );
}

/// After untrusted content, a later network call or protected write is stricter,
/// never looser; a recorded session round-trips through JSON.
#[test]
fn a_session_only_tightens_later_decisions() {
    let e = engine();
    let mut session = Session::new();
    assert!(session.is_clean());
    let mcp = Action::mcp(McpCall::new("mcp__web__fetch"));
    let before = e.decide_with(&mcp, &Facts::new(), &session);
    session.record(
        &e,
        &Action::fetch("https://docs.example/page"),
        &Facts::new(),
    );
    assert!(!session.is_clean());
    let text = serde_json::to_string(&session).unwrap();
    let restored: Session = serde_json::from_str(&text).unwrap();
    assert_eq!(restored, session);
    let write = Action::write("/p/.git/hooks/pre-commit");
    let after = e.decide_with(&write, &Facts::new(), &restored);
    assert!(after.verdict >= e.decide(&write).verdict);
    assert!(e.decide_with(&mcp, &Facts::new(), &restored).verdict >= before.verdict);
}

#[test]
fn paths_lists_what_a_call_reads_and_writes() {
    let e = engine();
    assert_eq!(
        e.paths(&Action::shell("cp ./a ~/b && cat ./a")),
        ["/h/b", "/p/a"]
    );
    assert!(e.paths(&Action::net("example.com")).is_empty());
}

#[test]
fn a_bad_context_is_an_error_not_an_engine() {
    let p = Policy::parse(DEFAULT_POLICY).unwrap();
    assert!(Engine::new(p.clone(), &Context::new("h", "/p")).is_err());
    let bad_move = Context::new("/h", "/p").moved_dir("/", "/srv");
    assert!(Engine::new(p, &bad_move).is_err());
}

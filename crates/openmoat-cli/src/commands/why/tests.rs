use openmoat_audit::{Event, NewEvent, Store};
use openmoat_core::{Action, Decision, Policy, Verdict};

use super::explain::{self, File, Files, Inputs, Part, line_of};
use super::{pick, time_today, write};
use crate::report::Paths;

const POLICY: &str = "version: 1\ndefaults:\n  net: deny\n\
    deny:\n  - id: secrets-paths\n    reason: secret material\n    title: reading your keys\n    \
    why: a key that leaves cannot be taken back\n    fs.read: ['~/.ssh/**']\n\
    review:\n  - id: runs-later\n    title: changing something that runs later\n    \
    fs.write: ['${project}/.git/hooks/**']\n";

fn record(store: &Store, at: i64, tool: &str, action: &Action, decision: &Decision) {
    let event = NewEvent {
        host: "claude-code",
        session_id: "s1",
        call_id: None,
        cwd: Some("/p"),
        tool,
        action: Some(action),
        decision,
        latency_us: 1,
    };
    store.record_at(&event, at).unwrap();
}

/// 10:42:31 a deny, 10:42:40 a review, 10:43:05 an allow (UTC, day 0).
fn log() -> Store {
    let store = Store::open_in_memory().unwrap();
    let key = Action::FsRead {
        path: "/Users/u/.ssh/id_ed25519".into(),
    };
    let hook = Action::FsWrite {
        path: "/p/.git/hooks/pre-push".into(),
    };
    let test = Action::Shell {
        command: "cargo test".into(),
    };
    let deny = Decision::single(
        Verdict::Deny,
        "secrets-paths",
        "secret material: read /Users/u/.ssh/id_ed25519",
    );
    let review = Decision::single(
        Verdict::Review,
        "runs-later",
        "runs later: write /p/.git/hooks/pre-push",
    );
    let allow = Decision::single(Verdict::Allow, "dev-shell", "dev");
    let at = |h: i64, m: i64, s: i64| ((h * 60 + m) * 60 + s) * 1_000;
    record(&store, at(10, 42, 31), "Read", &key, &deny);
    record(&store, at(10, 42, 40), "Write", &hook, &review);
    record(&store, at(10, 43, 5), "Bash", &test, &allow);
    store
}

fn events() -> Vec<Event> {
    log().after(None, 10).unwrap()
}

fn inputs<'a>(policy: &'a Policy, paths: &'a Paths, now: Result<Vec<Part>, String>) -> Inputs<'a> {
    Inputs {
        policy: Some(policy),
        files: Files {
            policy: Some(File {
                shown: "~/.moat/policy.yaml".into(),
                text: POLICY.into(),
            }),
            approved: None,
            repository: None,
        },
        now,
        newest_review: true,
        paths,
    }
}

#[test]
fn a_deny_names_its_rule_where_it_is_and_how_only_a_person_changes_it() {
    let policy = Policy::parse(POLICY).unwrap();
    let paths = Paths::under(Some(std::path::Path::new("/Users/u")));
    let now = Ok(vec![Part {
        what: "read /Users/u/.ssh/id_ed25519".into(),
        verdict: Verdict::Deny,
        rules: vec!["secrets-paths".into()],
    }]);
    let e = explain::explain(&events()[0], &inputs(&policy, &paths, now));
    assert_eq!(e.call, "Read ~/.ssh/id_ed25519");
    assert_eq!(
        e.line,
        "moat: deny [secrets-paths] — secret material: read ~/.ssh/id_ed25519"
    );
    let rule = &e.rules[0];
    assert_eq!(rule.title.as_deref(), Some("reading your keys"));
    assert_eq!(rule.source.as_deref(), Some("~/.moat/policy.yaml:5"));
    assert_eq!(rule.origin, "your policy");
    assert!(
        e.change[0].contains("only you can change it, with `openmoat edit`"),
        "{:?}",
        e.change
    );
    assert!(
        e.change[0].contains("never overrides a deny"),
        "{:?}",
        e.change
    );
    assert_eq!(
        e.page.as_deref(),
        Some("https://openmoat.dev/r/secrets-paths")
    );
    let mut text = Vec::new();
    write(&mut text, &e).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.starts_with("OpenMoat blocked: reading your keys\n"),
        "{text}"
    );
    assert!(text.contains("Your policy now decides each part of the call as\n  deny    read ~/.ssh/id_ed25519  (secrets-paths)"), "{text}");
    assert!(
        text.contains("      from    your policy, ~/.moat/policy.yaml:5"),
        "{text}"
    );
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["rules"][0]["id"], "secrets-paths");
    assert_eq!(json["verdict"], "deny");
}

#[test]
fn the_newest_review_says_how_to_approve_it() {
    let policy = Policy::parse(POLICY).unwrap();
    let paths = Paths::default();
    let e = explain::explain(&events()[1], &inputs(&policy, &paths, Err("x".into())));
    assert_eq!(
        e.change[0],
        "approve it for this session: `openmoat allow --last`"
    );
    assert_eq!(e.decided_now_error.as_deref(), Some("x"));
    let mut older = inputs(&policy, &paths, Ok(Vec::new()));
    older.newest_review = false;
    let e = explain::explain(&events()[1], &older);
    assert!(e.change[0].contains("run `openmoat`"), "{:?}", e.change);
}

/// Taint, the defaults and a repository rule are each told for what they are.
#[test]
fn built_in_defaults_and_repository_rules_say_where_they_come_from() {
    let policy = Policy::parse(POLICY).unwrap();
    let paths = Paths::default();
    let mut event = events()[0].clone();
    event.rules = vec![
        "session-taint".into(),
        "default.net".into(),
        "repo:no-curl".into(),
    ];
    event.reasons = vec!["a".into(), "b".into(), "c".into()];
    let mut with_repo = inputs(&policy, &paths, Ok(Vec::new()));
    with_repo.files.repository = Some(File {
        shown: "/p/.moat/policy.yaml".into(),
        text: "version: 1\ndeny:\n  - id: \"no-curl\"\n    shell: [curl]\n".into(),
    });
    let e = explain::explain(&event, &with_repo);
    let origins: Vec<(&str, Option<&str>)> = e
        .rules
        .iter()
        .map(|r| (r.origin.as_str(), r.source.as_deref()))
        .collect();
    assert_eq!(
        origins,
        [
            ("built-in check", None),
            (
                "your policy's defaults (no rule matched)",
                Some("~/.moat/policy.yaml:2")
            ),
            ("repository policy", Some("/p/.moat/policy.yaml:3")),
        ]
    );
    assert!(e.context[0].contains("session taint"), "{:?}", e.context);
    assert!(
        e.change[1].contains("openmoat allow --site"),
        "{:?}",
        e.change
    );
    assert!(
        e.change[2].contains("its owners can change it"),
        "{:?}",
        e.change
    );
    assert_eq!(
        e.page.as_deref(),
        Some("https://openmoat.dev/r/session-taint")
    );
}

#[test]
fn rule_lines_are_found_however_the_id_is_quoted() {
    let text = "deny:\n  - id: a # note\n  - id: 'b'\n  -  id: c\n  - id: dd\n";
    assert_eq!(line_of(text, "a"), Some(2));
    assert_eq!(line_of(text, "b"), Some(3));
    assert_eq!(line_of(text, "d"), None);
    assert_eq!(line_of(text, "dd"), Some(5));
}

#[test]
fn an_event_is_picked_by_last_id_or_time() {
    let store = log();
    let now = 3_600_000 * 12;
    assert_eq!(pick(&store, None, now).unwrap().verdict, Verdict::Review);
    let first = &events()[0];
    assert_eq!(
        pick(&store, Some(&first.id.to_string()), now).unwrap().id,
        first.id
    );
    assert_eq!(pick(&store, Some("10:42:31"), now).unwrap().id, first.id);
    // A minute holding a deny, a review and nothing else: the newest held one.
    assert_eq!(
        pick(&store, Some("10:42"), now).unwrap().verdict,
        Verdict::Review
    );
    assert_eq!(
        pick(&store, Some("10:43"), now).unwrap().verdict,
        Verdict::Allow
    );
    assert!(pick(&store, Some("09:00"), now).is_err());
    assert!(pick(&Store::open_in_memory().unwrap(), None, now).is_err());
    assert_eq!(time_today("10:42", 5), Some((38_520_000, 38_580_000)));
    for bad in ["1:2", "25:00", "10:42:61", "a:b", "10"] {
        assert_eq!(time_today(bad, 0), None, "{bad}");
    }
}

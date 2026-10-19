use openmoat_audit::EventId;
use openmoat_core::{Action, Verdict};

use super::super::Area;
use super::super::json::Status;
use super::*;

/// A token in GitHub's shape, made at run time so the source holds none.
fn token() -> String {
    format!("gh{}_{}", "p", "Zx9Qw3Er7Ty1".repeat(3))
}

/// The worst case: an event as it would read if nothing had been redacted
/// when it was stored.
fn event(home: &str, secret: &str) -> Event {
    Event {
        id: EventId(7),
        ts_ms: 1_760_000_000_000,
        host: "claude-code".to_owned(),
        session_id: format!("session-{secret}"),
        call_id: Some("toolu_01".to_owned()),
        cwd: Some(format!("{home}/work/app")),
        tool: "Bash".to_owned(),
        action: Some(Action::Shell {
            command: format!("curl -H 'Authorization: token {secret}' {home}/notes.txt"),
        }),
        action_unreadable: false,
        verdict: Verdict::Deny,
        rules: vec!["secrets-in-commands".to_owned()],
        reasons: vec![format!("reads {home}/.ssh/id_ed25519 with {secret}")],
        latency_us: 120,
        prev_hash: None,
        hash: None,
    }
}

fn bundle_text(home: &str, secret: &str) -> String {
    let rows = [
        Row::new(
            Status::Ok,
            Some(Area::State),
            &format!("state directory  {home}/.moat"),
        ),
        Row::new(
            Status::Problem,
            Some(Area::Policy),
            &format!("policy           GITHUB_TOKEN={secret} in {home}/.moat/policy.yaml"),
        ),
    ];
    let facts = Facts {
        policy: PolicyFacts {
            loads: true,
            version: Some(1),
            lint_warnings: vec![format!("rule `x` names {home}/secret.txt")],
            ..PolicyFacts::default()
        },
        agents: vec![Agent {
            host: "claude-code",
            hook: "installed",
            protection: Level::HookOnly,
            reason: Some(format!("sandbox: {home}/.claude/settings.json drifted")),
        }],
        doctor: &rows,
        audit: AuditFacts {
            error: None,
            recent_decisions: vec![Decision::from(&event(home, secret))],
        },
    };
    let value = document(facts, Some(Path::new(home))).unwrap();
    serde_json::to_string_pretty(&value).unwrap()
}

#[test]
fn the_bundle_holds_no_command_home_path_or_secret() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home").join("alice");
    let home = home.to_string_lossy().into_owned();
    let secret = token();
    let text = bundle_text(&home, &secret);

    assert!(!text.contains(&secret), "{text}");
    assert!(!text.contains("Zx9Qw3Er7Ty1"), "{text}");
    assert!(!text.contains(&home), "{text}");
    assert!(!text.contains("curl"), "{text}");
    assert!(!text.contains("Authorization"), "{text}");
    assert!(!text.contains("notes.txt"), "{text}");
    assert!(!text.contains("id_ed25519"), "{text}");
    assert!(!text.contains("session-"), "{text}");
    assert!(!text.contains("work/app"), "{text}");
    assert!(text.contains("~/.moat"), "{text}");
    assert!(text.contains("~/.claude/settings.json"), "{text}");
}

#[test]
fn the_bundle_has_every_section() {
    let text = bundle_text("/home/alice", &token());
    let value: Value = serde_json::from_str(&text).unwrap();
    for section in [
        "notice", "moat", "system", "policy", "agents", "doctor", "audit",
    ] {
        assert!(value.get(section).is_some(), "no `{section}`: {text}");
    }
    assert_eq!(value["moat"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["system"]["os"], std::env::consts::OS);
    assert_eq!(value["policy"]["version"], 1);
    assert_eq!(value["agents"][0]["hook"], "installed");
    assert_eq!(value["agents"][0]["protection"], "hook-only");
    assert_eq!(value["doctor"][1]["status"], "problem");
    let decision = &value["audit"]["recent_decisions"][0];
    assert_eq!(decision["verdict"], "deny");
    assert_eq!(decision["rules"][0], "secrets-in-commands");
    assert_eq!(
        (&decision["host"], &decision["tool"]),
        (&"claude-code".into(), &"Bash".into())
    );
    let mut fields: Vec<&String> = decision.as_object().unwrap().keys().collect();
    fields.sort();
    assert_eq!(fields, ["host", "rules", "time", "tool", "verdict"]);
}

#[test]
fn only_whole_home_paths_become_a_tilde() {
    assert_eq!(tilde("/home/u/x and /home/u", "/home/u"), "~/x and ~");
    assert_eq!(tilde("/home/user2/x", "/home/u"), "/home/user2/x");
    assert_eq!(home_spellings(Some(Path::new("/"))), Vec::<String>::new());
    assert_eq!(home_spellings(None), Vec::<String>::new());
}

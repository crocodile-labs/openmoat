mod chain;
mod export;

use super::*;

#[cfg(unix)]
#[test]
fn database_and_wal_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let store = Store::open(&path).unwrap();
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    let a = Action::Shell {
        command: "git status".into(),
    };
    store.record(&sample(&d, &a)).unwrap();
    for name in ["audit.db", "audit.db-wal", "audit.db-shm"] {
        let mode = std::fs::metadata(dir.path().join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{name}");
    }
}

fn decision(verdict: Verdict, rule: &str, reason: &str) -> Decision {
    let mut d = Decision::new(verdict);
    d.rules.push(rule.to_owned());
    d.reasons.push(reason.to_owned());
    d
}

fn sample<'a>(decision: &'a Decision, action: &'a Action) -> NewEvent<'a> {
    NewEvent {
        host: "claude-code",
        session_id: "s1",
        call_id: Some("c1"),
        cwd: Some("/p"),
        tool: "Bash",
        action: Some(action),
        decision,
        latency_us: 1200,
    }
}

#[test]
fn record_and_read_back() {
    let store = Store::open_in_memory().unwrap();
    let d = decision(
        Verdict::Deny,
        "secrets-paths",
        "secret material: read /h/.ssh/id_rsa",
    );
    let a = Action::Shell {
        command: "cat ~/.ssh/id_rsa".into(),
    };
    let id = store.record(&sample(&d, &a)).unwrap();
    let event = store.get(id).unwrap().expect("stored");
    assert_eq!(event.verdict, Verdict::Deny);
    assert_eq!(event.rules, ["secrets-paths"]);
    assert_eq!(event.action, Some(a));
    assert_eq!(event.tool, "Bash");
    assert_eq!(event.latency_us, 1200);
    assert_eq!(store.count().unwrap(), 1);
    assert!(store.get(EventId(999)).unwrap().is_none());
}

#[test]
fn redaction_keeps_stored_json_valid_and_secret_free() {
    let store = Store::open_in_memory().unwrap();
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    for command in [
        r#"curl -H "X-Api-Key: abc123def456" https://api.github.com"#,
        r#"export PASSWORD="hunter2""#,
        "git clone https://user:s3cretpw@github.com/x/y",
    ] {
        let a = Action::Shell {
            command: command.into(),
        };
        store.record(&sample(&d, &a)).unwrap();
    }
    let events = store.recent(10).unwrap();
    assert_eq!(events.len(), 3);
    let raw: Vec<String> = {
        let mut stmt = store.conn.prepare("SELECT action FROM events").unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        rows.map(Result::unwrap).collect()
    };
    for text in &raw {
        serde_json::from_str::<serde_json::Value>(text).expect("stored action is valid JSON");
        for secret in ["abc123def456", "hunter2", "s3cretpw"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
    }
}

#[test]
fn a_corrupt_action_cell_does_not_break_queries() {
    let store = Store::open_in_memory().unwrap();
    let d = decision(Verdict::Deny, "secrets-paths", "secret");
    let a = Action::Shell {
        command: "cat ~/.ssh/id_rsa".into(),
    };
    let id = store.record(&sample(&d, &a)).unwrap();
    store
        .conn
        .execute(
            "UPDATE events SET action = '{\"shell\":{\"command\":\"broken' WHERE id = ?1",
            params![id.0],
        )
        .unwrap();
    let event = store.get(id).unwrap().expect("row still readable");
    assert_eq!(event.action, None);
    assert!(
        event.action_unreadable,
        "the row says its action is unreadable"
    );
    assert_eq!(event.verdict, Verdict::Deny);
    assert_eq!(event.rules, ["secrets-paths"]);
    assert_eq!(store.recent(5).unwrap().len(), 1);
    let ungoverned = store
        .record(&NewEvent {
            action: None,
            ..sample(&d, &a)
        })
        .unwrap();
    assert!(!store.get(ungoverned).unwrap().unwrap().action_unreadable);
}

#[test]
fn secrets_are_redacted_before_storage() {
    let store = Store::open_in_memory().unwrap();
    let d = decision(
        Verdict::Allow,
        "dev-shell",
        "shell with token=ghp_abcdefghijklmnopqrstuvwxyz0123",
    );
    let a = Action::Shell {
        command: "curl -H 'Authorization: Bearer abcdefghijkl' https://api.github.com".into(),
    };
    let id = store.record(&sample(&d, &a)).unwrap();
    let event = store.get(id).unwrap().unwrap();
    let Some(Action::Shell { command }) = event.action else {
        panic!("shell action")
    };
    assert!(command.contains("Bearer [redacted]"), "{command}");
    assert!(event.reasons[0].contains("[redacted]"));
}

#[test]
fn known_secret_values_are_masked_in_every_agent_text_and_the_chain_holds() {
    /// Generated for the test; no real secret is used.
    const FAKE: &str = "Zq81-fake-unknown-format-c3";
    let known = KnownSecrets::new([FAKE]).unwrap();
    let store = Store::open_in_memory().unwrap().with_secrets(known);
    let d = decision(Verdict::Deny, "proxy-secret", &format!("to {FAKE}.x.test"));
    let a = Action::Net {
        url: format!("https://x.test/?k={FAKE}"),
    };
    let cwd = format!("/p/{FAKE}");
    let id = store
        .record(&NewEvent {
            cwd: Some(&cwd),
            ..sample(&d, &a)
        })
        .unwrap();
    let event = store.get(id).unwrap().unwrap();
    let stored = serde_json::to_string(&event).unwrap();
    assert!(!stored.contains(FAKE), "{stored}");
    assert_eq!(event.cwd.as_deref(), Some("/p/[redacted]"));
    let report = store.verify_chain().unwrap();
    assert!(report.broken.is_none() && report.events == 1);
}

#[test]
fn known_secret_values_are_masked_in_the_host_ids_and_tool_name() {
    /// Generated for the test; no real secret is used.
    const FAKE: &str = "Zq81-fake-unknown-format-c3";
    let store = Store::open_in_memory()
        .unwrap()
        .with_secrets(KnownSecrets::new([FAKE]).unwrap());
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    let a = Action::Shell {
        command: "git status".into(),
    };
    let [host, session, call, tool] = ["h", "s", "c", "t"].map(|f| format!("{f}-{FAKE}"));
    let id = store
        .record(&NewEvent {
            host: &host,
            session_id: &session,
            call_id: Some(&call),
            tool: &tool,
            ..sample(&d, &a)
        })
        .unwrap();
    let event = store.get(id).unwrap().unwrap();
    assert_eq!(
        [&event.host, &event.session_id, &event.tool],
        ["h-[redacted]", "s-[redacted]", "t-[redacted]"]
    );
    assert_eq!(event.call_id.as_deref(), Some("c-[redacted]"));
    assert_eq!(store.session(&session).unwrap(), [event]);
    assert!(store.verify_chain().unwrap().broken.is_none());
}

#[test]
fn recent_and_session_queries() {
    let store = Store::open_in_memory().unwrap();
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    let a = Action::Shell {
        command: "git status".into(),
    };
    for session in ["s1", "s2", "s1"] {
        store
            .record(&NewEvent {
                session_id: session,
                ..sample(&d, &a)
            })
            .unwrap();
    }
    let recent = store.recent(2).unwrap();
    assert_eq!(recent.len(), 2);
    assert!(recent[0].id.0 > recent[1].id.0);
    assert_eq!(store.session("s1").unwrap().len(), 2);
    assert!(store.session("none").unwrap().is_empty());
}

#[test]
fn ungoverned_event_has_no_action() {
    let store = Store::open_in_memory().unwrap();
    let d = decision(Verdict::Allow, "ungoverned", "tool outside policy scope");
    let id = store
        .record(&NewEvent {
            action: None,
            tool: "TodoWrite",
            ..sample(
                &d,
                &Action::Shell {
                    command: String::new(),
                },
            )
        })
        .unwrap();
    assert_eq!(store.get(id).unwrap().unwrap().action, None);
}

#[test]
fn event_ids_are_hex() {
    assert_eq!(EventId(31).to_string(), "1f");
    assert_eq!("1f".parse::<EventId>().unwrap(), EventId(31));
    assert_eq!("#1F".parse::<EventId>().unwrap(), EventId(31));
    assert!("zz".parse::<EventId>().is_err());
    assert!("0".parse::<EventId>().is_err());

    assert_eq!(serde_json::to_string(&EventId(31)).unwrap(), r#""1f""#);
    assert_eq!(
        serde_json::from_str::<EventId>(r#""1f""#).unwrap(),
        EventId(31)
    );
    assert_eq!(serde_json::from_str::<EventId>("31").unwrap(), EventId(31));
    assert!(serde_json::from_str::<EventId>(r#""zz""#).is_err());
}

#[test]
fn file_store_round_trip_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let d = decision(Verdict::Ask, "installs", "new dependency");
    let a = Action::Shell {
        command: "npm install x".into(),
    };
    let id = Store::open(&path).unwrap().record(&sample(&d, &a)).unwrap();
    let reopened = Store::open_read_only(&path).unwrap();
    assert_eq!(reopened.get(id).unwrap().unwrap().verdict, Verdict::Ask);
}

#[test]
fn open_existing_refuses_a_missing_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    assert!(Store::open_existing(&path).is_err());
    assert!(
        !path.exists(),
        "a deleted audit log is not silently recreated"
    );
    Store::open(&path).unwrap();
    assert!(Store::open_existing(&path).is_ok());
}

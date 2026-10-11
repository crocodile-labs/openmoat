use openmoat_core::{Action, Decision, Verdict};

use super::*;

fn record(store: &Store, host: &str, session: &str, command: &str, ts_ms: i64) {
    let mut decision = Decision::new(Verdict::Ask);
    decision.rules.push("installs".to_owned());
    decision.reasons.push(format!("asked about {command}"));
    let action = Action::Shell {
        command: command.to_owned(),
    };
    store
        .record_at(
            &NewEvent {
                host,
                session_id: session,
                call_id: None,
                cwd: Some("/p"),
                tool: "Bash",
                action: Some(&action),
                decision: &decision,
                latency_us: 7,
            },
            ts_ms,
        )
        .unwrap();
}

fn seeded() -> Store {
    let store = Store::open_in_memory().unwrap();
    record(&store, "claude-code", "s1", "npm install a", 1_000);
    record(&store, "cursor", "c1", "npm install b", 2_000);
    record(&store, "claude-code", "s2", "npm install c", 3_000);
    store
}

fn ids(events: &[ExportedEvent]) -> Vec<i64> {
    events.iter().map(|e| e.id.0).collect()
}

#[test]
fn export_carries_stored_cells_and_chain_links() {
    let store = seeded();
    let exported = store.export(&ExportFilter::default()).unwrap();
    assert_eq!(ids(&exported), [1, 2, 3]);
    let stored: String = store
        .conn
        .query_row("SELECT action FROM events WHERE id = 2", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        exported[1].action.get(),
        stored,
        "the stored text, byte for byte"
    );
    assert_eq!(exported[0].prev_hash, GENESIS);
    for (event, line) in store.session("s1").unwrap().iter().zip(&exported) {
        assert_eq!(event.hash.as_deref(), Some(line.hash.as_str()));
    }
    let line = serde_json::to_string(&exported[1]).unwrap();
    assert!(
        line.starts_with(r#"{"format":"moat-audit-export-v1","id":"2","#),
        "{line}"
    );
    assert!(line.contains(r#""rules":["installs"]"#), "{line}");
    assert!(!line.contains('\n'));
}

#[test]
fn export_filters_by_time_host_and_session() {
    let store = seeded();
    let export = |filter: ExportFilter<'_>| ids(&store.export(&filter).unwrap());
    let since = |since_ms| ExportFilter {
        since_ms,
        ..ExportFilter::default()
    };
    assert_eq!(export(since(2_000)), [2, 3]);
    let claude = ExportFilter {
        host: Some("claude-code"),
        ..ExportFilter::default()
    };
    assert_eq!(export(claude), [1, 3]);
    let s2 = ExportFilter {
        session_id: Some("s2"),
        ..ExportFilter::default()
    };
    assert_eq!(export(s2), [3]);
    assert_eq!(
        export(ExportFilter {
            since_ms: 2_000,
            ..claude
        }),
        [3]
    );
}

#[test]
fn export_holds_only_redacted_text() {
    let store = Store::open_in_memory().unwrap();
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    record(
        &store,
        "codex",
        "k1",
        &format!("curl -H 'Authorization: Bearer {secret}' https://x"),
        1,
    );
    let exported = store.export(&ExportFilter::default()).unwrap();
    let line = serde_json::to_string(&exported).unwrap();
    assert!(!line.contains(secret), "{line}");
    assert!(line.contains("curl"), "{line}");
}

#[test]
fn export_leaves_out_events_from_before_the_chain() {
    let store = seeded();
    store
        .conn
        .execute(
            "UPDATE events SET hash = NULL, prev_hash = NULL WHERE id = 1",
            [],
        )
        .unwrap();
    assert_eq!(
        ids(&store.export(&ExportFilter::default()).unwrap()),
        [2, 3]
    );
}

fn export_text(store: &Store, filter: &ExportFilter<'_>) -> String {
    store
        .export(filter)
        .unwrap()
        .iter()
        .map(|e| serde_json::to_string(e).unwrap() + "\n")
        .collect()
}

fn broken_at(text: &str) -> Option<(usize, Option<i64>, BreakKind)> {
    verify_export(text, None)
        .broken
        .map(|b| (b.line, b.id.map(|id| id.0), b.kind))
}

#[test]
fn an_untouched_export_verifies_and_reports_its_head() {
    let store = seeded();
    let text = export_text(&store, &ExportFilter::default());
    let head = store.get(EventId(3)).unwrap().unwrap().hash.unwrap();
    let report = verify_export(&text, Some(&head));
    assert_eq!(report.broken, None);
    assert_eq!(report.events, 3);
    assert_eq!(
        (report.first_id, report.last_id),
        (Some(EventId(1)), Some(EventId(3)))
    );
    assert!(report.from_genesis);
    assert_eq!(report.gaps, 0);
    assert_eq!(report.head.as_deref(), Some(head.as_str()));
    assert_eq!(report.anchor, AnchorCheck::Found);
    let crlf = text.replace('\n', "\r\n") + "\n";
    assert_eq!(verify_export(&crlf, None).events, 3, "CRLF and blank lines");
}

#[test]
fn verifying_without_an_anchor_says_the_export_is_not_anchored() {
    let text = export_text(&seeded(), &ExportFilter::default());
    let report = verify_export(&text, None);
    assert_eq!(report.broken, None);
    assert_eq!(report.anchor, AnchorCheck::NotAnchored);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["anchor"], "not_anchored");
}

#[test]
fn an_edited_line_is_named() {
    let text = export_text(&seeded(), &ExportFilter::default());
    for (from, to) in [
        ("npm install b", "npm install x"),
        (r#""verdict":"ask""#, r#""verdict":"allow""#),
        (r#"{"shell":{"#, r#"{"shell": {"#),
    ] {
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        lines[1] = lines[1].replacen(from, to, 1);
        assert_eq!(
            broken_at(&lines.join("\n")),
            Some((2, Some(2), BreakKind::Edited)),
            "{from} -> {to}"
        );
    }
}

#[test]
fn reordered_and_foreign_lines_break_the_export() {
    let text = export_text(&seeded(), &ExportFilter::default());
    let lines: Vec<&str> = text.lines().collect();
    let swapped = [lines[1], lines[0], lines[2]].join("\n");
    assert_eq!(broken_at(&swapped), Some((2, Some(1), BreakKind::Unlinked)));
    let extra = lines[2].replacen('{', r#"{"note":"x","#, 1);
    let added = [lines[0], lines[1], &extra].join("\n");
    assert_eq!(broken_at(&added), Some((3, None, BreakKind::Unreadable)));
    assert_eq!(
        broken_at("not json"),
        Some((1, None, BreakKind::Unreadable))
    );
}

#[test]
fn filtered_and_truncated_exports_verify_with_gaps_and_a_different_head() {
    let store = seeded();
    let claude = ExportFilter {
        host: Some("claude-code"),
        ..ExportFilter::default()
    };
    let filtered = verify_export(&export_text(&store, &claude), None);
    assert_eq!(
        (filtered.events, filtered.gaps, filtered.broken),
        (2, 1, None)
    );

    let full = export_text(&store, &ExportFilter::default());
    let head = verify_export(&full, None).head.unwrap();
    let truncated = full.lines().take(2).collect::<Vec<_>>().join("\n");
    let report = verify_export(&truncated, Some(&head));
    assert_eq!(
        report.broken, None,
        "dropping the newest events leaves a valid file"
    );
    assert_eq!(
        report.anchor,
        AnchorCheck::Missing,
        "but the anchored head is missing"
    );

    let later = ExportFilter {
        since_ms: 2_000,
        ..ExportFilter::default()
    };
    assert!(!verify_export(&export_text(&store, &later), None).from_genesis);
}

#[test]
fn an_exported_event_reads_back_as_the_stored_event() {
    let store = seeded();
    for line in export_text(&store, &ExportFilter::default()).lines() {
        let exported: ExportedEvent = serde_json::from_str(line).unwrap();
        let stored = store.get(exported.id).unwrap().unwrap();
        assert_eq!(exported.to_event().unwrap(), stored);
    }
    let mut bad: ExportedEvent = serde_json::from_str(
        export_text(&store, &ExportFilter::default())
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    bad.verdict = "maybe".to_owned();
    assert!(matches!(
        bad.to_event(),
        Err(StoreError::Decode { id: EventId(1), .. })
    ));
}

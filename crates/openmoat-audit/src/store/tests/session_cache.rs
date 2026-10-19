//! The session cache (#570): a convenience beside the events, never ahead of
//! them and never moved back, with a row per digest of a session.

use super::*;

fn shell(command: &str) -> Action {
    Action::Shell {
        command: command.into(),
    }
}

#[test]
fn session_after_returns_only_later_events_of_that_session() {
    let store = Store::open_in_memory().unwrap();
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    let (a, b) = (shell("ls"), shell("pwd"));
    let first = store.record(&sample(&d, &a)).unwrap();
    let mut other = sample(&d, &a);
    other.session_id = "s2";
    store.record(&other).unwrap();
    let second = store.record(&sample(&d, &b)).unwrap();
    let ids = |after| -> Vec<i64> {
        store
            .session_after("s1", after)
            .unwrap()
            .iter()
            .map(|e| e.id.0)
            .collect()
    };
    assert_eq!(ids(EventId(0)), [first.0, second.0]);
    assert_eq!(ids(first), [second.0]);
    assert!(ids(second).is_empty());
}

#[test]
fn session_has_finds_an_event_by_session_host_and_call_id() {
    let store = Store::open_in_memory().unwrap();
    assert!(!store.session_has("s1", "claude-code", "c1").unwrap());
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    let action = shell("ls");
    store.record(&sample(&d, &action)).unwrap();
    assert!(store.session_has("s1", "claude-code", "c1").unwrap());
    assert!(!store.session_has("s2", "claude-code", "c1").unwrap());
    assert!(!store.session_has("s1", "codex", "c1").unwrap());
    assert!(!store.session_has("s1", "claude-code", "c2").unwrap());
}

#[test]
fn session_page_returns_at_most_limit_events_in_order() {
    let store = Store::open_in_memory().unwrap();
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    let action = shell("ls");
    let ids: Vec<i64> = (0..5)
        .map(|_| store.record(&sample(&d, &action)).unwrap().0)
        .collect();
    let page = |after, limit| -> Vec<i64> {
        store
            .session_page("s1", EventId(after), limit)
            .unwrap()
            .iter()
            .map(|e| e.id.0)
            .collect()
    };
    assert_eq!(page(0, 2), ids[..2]);
    assert_eq!(page(ids[1], 2), ids[2..4]);
    assert_eq!(page(ids[3], 2), ids[4..]);
    assert_eq!(page(0, usize::MAX), ids);
}

fn cached(digest: &str, upto: i64, state: &str) -> Cached {
    Cached {
        digest: digest.into(),
        upto: EventId(upto),
        state: state.into(),
    }
}

#[test]
fn the_cache_is_absent_until_written_and_never_moves_back() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(
        store.session_cache("s1", "claude-code", "d1").unwrap(),
        None
    );
    store
        .set_session_cache("s1", "claude-code", &cached("d1", 5, "five"))
        .unwrap();
    // a slower guard that read fewer events does not replace it
    store
        .set_session_cache("s1", "claude-code", &cached("d1", 3, "three"))
        .unwrap();
    assert_eq!(
        store.session_cache("s1", "claude-code", "d1").unwrap(),
        Some(cached("d1", 5, "five"))
    );
    // another digest (a working directory, a policy) has a row of its own
    store
        .set_session_cache("s1", "claude-code", &cached("d2", 2, "two"))
        .unwrap();
    assert_eq!(
        store.session_cache("s1", "claude-code", "d2").unwrap(),
        Some(cached("d2", 2, "two"))
    );
    assert_eq!(
        store.session_cache("s1", "claude-code", "d1").unwrap(),
        Some(cached("d1", 5, "five"))
    );
    assert_eq!(store.session_cache("s1", "codex", "d1").unwrap(), None);
    assert_eq!(
        store.session_cache("s2", "claude-code", "d1").unwrap(),
        None
    );
}

/// A session keeps its most recently written rows; the oldest digest goes,
/// and other sessions keep theirs.
#[test]
fn a_session_keeps_a_bounded_number_of_rows() {
    let store = Store::open_in_memory().unwrap();
    store
        .set_session_cache("s2", "claude-code", &cached("d0", 1, "other"))
        .unwrap();
    for n in 0..=16 {
        store
            .set_session_cache("s1", "claude-code", &cached(&format!("d{n}"), 1, "x"))
            .unwrap();
    }
    // d0 is written again (a later event), so d1 is the least recent
    store
        .set_session_cache("s1", "claude-code", &cached("d0", 2, "y"))
        .unwrap();
    assert_eq!(
        store.session_cache("s1", "claude-code", "d1").unwrap(),
        None
    );
    for n in [0, 2, 16] {
        assert!(
            store
                .session_cache("s1", "claude-code", &format!("d{n}"))
                .unwrap()
                .is_some(),
            "d{n}"
        );
    }
    assert_eq!(
        store.session_cache("s2", "claude-code", "d0").unwrap(),
        Some(cached("d0", 1, "other"))
    );
}

/// Another guard holding the write lock (it is recording) makes the cache
/// write give up at once instead of waiting; the older row stays, and the same
/// handle then waits for the lock as usual to record.
#[test]
fn a_cache_write_is_skipped_not_blocked_while_another_connection_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let store = Store::open(&path).unwrap();
    let cached = |upto, state: &str| Cached {
        digest: "d1".into(),
        upto: EventId(upto),
        state: state.into(),
    };
    assert!(
        store
            .try_set_session_cache("s1", "claude-code", &cached(1, "one"))
            .unwrap()
    );

    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = std::time::Instant::now();
    let written = store
        .try_set_session_cache("s1", "claude-code", &cached(2, "two"))
        .unwrap();
    let waited = started.elapsed();
    assert!(!written);
    assert!(
        waited < std::time::Duration::from_millis(BUSY_TIMEOUT_MS / 2),
        "waited {waited:?}"
    );
    assert_eq!(
        store.session_cache("s1", "claude-code", "d1").unwrap(),
        Some(cached(1, "one"))
    );

    // The busy timeout is back: a record waits out a short lock and succeeds.
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        writer.execute_batch("COMMIT").unwrap();
    });
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    let action = shell("ls");
    store.record(&sample(&d, &action)).unwrap();
    release.join().unwrap();
    assert!(
        store
            .try_set_session_cache("s1", "claude-code", &cached(2, "two"))
            .unwrap()
    );
    assert_eq!(
        store.session_cache("s1", "claude-code", "d1").unwrap(),
        Some(cached(2, "two"))
    );
}

//! The session cache (#570): a convenience beside the events, never ahead of
//! them and never moved back.

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
fn the_cache_is_absent_until_written_and_never_moves_back() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.session_cache("s1", "claude-code").unwrap(), None);
    let cached = |digest: &str, upto, state: &str| Cached {
        digest: digest.into(),
        upto: EventId(upto),
        state: state.into(),
    };
    store
        .set_session_cache("s1", "claude-code", &cached("d1", 5, "five"))
        .unwrap();
    // a slower guard that read fewer events does not replace it
    store
        .set_session_cache("s1", "claude-code", &cached("d1", 3, "three"))
        .unwrap();
    assert_eq!(
        store.session_cache("s1", "claude-code").unwrap(),
        Some(cached("d1", 5, "five"))
    );
    // another digest (policy, version) replaces it whatever its row
    store
        .set_session_cache("s1", "claude-code", &cached("d2", 2, "two"))
        .unwrap();
    assert_eq!(
        store.session_cache("s1", "claude-code").unwrap(),
        Some(cached("d2", 2, "two"))
    );
    assert_eq!(store.session_cache("s1", "codex").unwrap(), None);
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
        store.session_cache("s1", "claude-code").unwrap(),
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
        store.session_cache("s1", "claude-code").unwrap(),
        Some(cached(2, "two"))
    );
}

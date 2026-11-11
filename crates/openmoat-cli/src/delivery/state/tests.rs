use super::*;

#[test]
fn the_wait_doubles_to_a_cap_and_a_longer_retry_after_wins() {
    assert_eq!(backoff(1, None, 0.0), FIRST_WAIT);
    assert_eq!(backoff(2, None, 0.0), FIRST_WAIT * 2);
    assert_eq!(backoff(4, None, 0.0), FIRST_WAIT * 8);
    assert_eq!(backoff(30, None, 0.0), MAX_WAIT);
    assert_eq!(backoff(u32::MAX, None, 1.0), MAX_WAIT + MAX_WAIT / 5);
    assert_eq!(backoff(1, Some(120), 0.0), Duration::from_secs(120));
    assert_eq!(backoff(1, Some(1), 0.0), FIRST_WAIT);
    assert_eq!(backoff(1, Some(u64::MAX), 0.0), MAX_RETRY_AFTER);
}

#[test]
fn a_failure_waits_a_refusal_pauses_and_a_success_clears_both() {
    let mut state = State::default();
    assert!(state.due(0));
    state.failed("HTTP 503".to_owned(), None, 1_000, 0.0);
    assert!(!state.due(1_000));
    assert!(state.due(6_000));
    state.pause("HTTP 401".to_owned(), 7_000);
    assert!(!state.due(i64::MAX));
    state.gaps.push(Gap {
        first: EventId(1),
        last: EventId(2),
        count: 2,
        reason: openmoat_audit::delivery::GapReason::BacklogFull,
    });
    state.accepted(Some(EventId(9)), 3, 8_000);
    assert!(state.due(8_000));
    assert_eq!(state.cursor, Some(EventId(9)));
    assert_eq!((state.failures, state.delivered), (0, 3));
    assert_eq!(state.gaps, Vec::new());
    assert_eq!(state.paused, None);
    // The failure stays for `status`.
    assert_eq!(state.last_error.as_deref(), Some("HTTP 401"));
}

/// Every state a run saves reads back as it was: before the first run,
/// at the start with no event sent (cursor `0`), after a failure there,
/// and after a success with a gap.
#[test]
fn every_saved_state_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hook.json");
    let fresh = State::default();
    let mut start = State {
        cursor: Some(EventId(0)),
        ..State::default()
    };
    let empty = start.clone();
    start.failed("HTTP 503".to_owned(), Some(30), 1_000, 0.5);
    let failed = start.clone();
    let mut done = failed.clone();
    done.gaps.push(Gap {
        first: EventId(1),
        last: EventId(0x1f),
        count: 31,
        reason: openmoat_audit::delivery::GapReason::BacklogFull,
    });
    done.accepted(Some(EventId(0x2a)), 11, 2_000);
    for state in [fresh, empty, failed, done] {
        state.save(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), state, "{text}");
    }
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(r#""cursor": "2a""#), "{text}");
    std::fs::write(&path, r#"{"cursor": "-1"}"#).unwrap();
    assert!(State::load(&path).is_err());
}

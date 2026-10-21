use std::sync::Mutex;

use super::*;
use crate::audit::RecordError;

/// Each row's rule and reason.
#[derive(Default)]
struct Rows(Mutex<Vec<(String, String)>>);

impl Recorder for Rows {
    fn record(&self, c: &Connection<'_>) -> Result<(), RecordError> {
        assert!(c.destination.is_none() && c.session.is_none());
        self.0
            .lock()
            .unwrap()
            .push((c.decision.rules[0].clone(), c.decision.reasons[0].clone()));
        Ok(())
    }
}

#[test]
fn a_flood_of_refusals_is_one_row_per_interval_with_its_count() {
    let rows = Rows::default();
    let refusals = Refusals::default();
    let start = Instant::now();
    // The first is recorded at once; the next 99 within the interval are counted.
    for i in 0..100 {
        refusals.refused(Full::Slots, &rows, start + Duration::from_millis(i));
    }
    refusals.refused(Full::Pending, &rows, start);
    let later = start + INTERVAL;
    refusals.flush(&rows, start + Duration::from_secs(1));
    assert_eq!(
        rows.0.lock().unwrap().len(),
        2,
        "nothing more before the interval"
    );
    refusals.flush(&rows, later);
    refusals.flush(&rows, later + INTERVAL);
    let rows = rows.0.into_inner().unwrap();
    assert!(rows.iter().all(|(rule, _)| rule == RULE_CAPACITY));
    let reasons: Vec<&str> = rows.iter().map(|(_, why)| why.as_str()).collect();
    assert_eq!(reasons.len(), 3, "{reasons:?}");
    assert!(
        reasons[0].starts_with("1 connection refused")
            && reasons[0].contains("too many connections")
    );
    assert!(reasons[1].starts_with("1 connection refused") && reasons[1].contains("authenticate"));
    assert!(
        reasons[2].starts_with("99 connections refused"),
        "{reasons:?}"
    );
}

/// Fails every record, keeping the failures it is told about.
#[derive(Default)]
struct Failing(Mutex<Vec<String>>);

impl Recorder for Failing {
    fn record(&self, _: &Connection<'_>) -> Result<(), RecordError> {
        Err(RecordError("disk full".to_owned()))
    }

    fn unrecorded(&self, error: &RecordError) {
        self.0.lock().unwrap().push(error.to_string());
    }
}

#[test]
fn a_row_that_cannot_be_written_is_reported() {
    let failing = Failing::default();
    Refusals::default().refused(Full::Slots, &failing, Instant::now());
    assert_eq!(
        *failing.0.lock().unwrap(),
        ["audit log unavailable: disk full"]
    );
}

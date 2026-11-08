//! Requests refused before anyone authenticated, in the audit log.
//!
//! Any local process can connect to the proxy's port and send a request with
//! a wrong credential (`407`) or a head that is not HTTP (`400`). Each is
//! refused; a row for each would let that process grow the audit log without
//! limit, and once the log cannot be written the proxy refuses everything.
//! So the first refusal of each kind is recorded as it was, the ones within
//! [`INTERVAL`] after it are counted, and the next row says how many it stands
//! for ([`crate::coalesce`]). The peer is not part of the kind: every peer of
//! a loopback port is this machine, and a process can pick its own port.

use std::time::Instant;

use openmoat_core::{Decision, Verdict};

use super::capacity::INTERVAL;
use crate::audit::{Connection, Recorder};
use crate::coalesce::{Coalesce, counted};
use crate::decide::RULE_REQUEST;
use crate::session::RULE_SESSION;

/// What was refused before a credential was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unauthenticated {
    /// A missing or invalid session credential (`407`).
    Credential,
    /// A request head the proxy could not read (`400`).
    Head,
}

impl Unauthenticated {
    const ALL: [Self; 2] = [Self::Credential, Self::Head];

    fn rule(self) -> &'static str {
        match self {
            Self::Credential => RULE_SESSION,
            Self::Head => RULE_REQUEST,
        }
    }

    fn what(self) -> &'static str {
        match self {
            Self::Credential => "without a valid session credential",
            Self::Head => "whose head could not be read",
        }
    }
}

/// The refusals before authentication of one [`Proxy::serve`](crate::Proxy::serve).
#[derive(Debug, Default)]
pub(super) struct Noise {
    counts: Coalesce<2>,
}

impl Noise {
    /// The row to record for one refusal of `kind`, decided as `decision`:
    /// `decision` itself for the first in [`INTERVAL`], the count with its
    /// reason after that, `None` while it is counted for a later row.
    pub(super) fn row(
        &self,
        kind: Unauthenticated,
        decision: &Decision,
        now: Instant,
    ) -> Option<Decision> {
        let count = self.counts.refused(kind as usize, now)?;
        if count == 1 {
            return Some(decision.clone());
        }
        let this = decision.reasons.first().map_or("", String::as_str);
        Some(Decision::single(
            Verdict::Deny,
            kind.rule(),
            format!(
                "{} {} refused since the last such row (at most one per {} s); the last: {this}",
                counted(count, "request", "requests"),
                kind.what(),
                INTERVAL.as_secs()
            ),
        ))
    }

    /// Record the refusals counted since the last row, where [`INTERVAL`] has
    /// passed: called as connections are accepted, so a flood that ends is
    /// still recorded.
    pub(super) fn flush(&self, recorder: &dyn Recorder, now: Instant) {
        for (index, count) in self.counts.due(now) {
            let Some(kind) = Unauthenticated::ALL.get(index) else {
                continue;
            };
            let decision = Decision::single(
                Verdict::Deny,
                kind.rule(),
                format!(
                    "{} {} refused since the last such row (at most one per {} s)",
                    counted(count, "request", "requests"),
                    kind.what(),
                    INTERVAL.as_secs()
                ),
            );
            let connection = Connection {
                session: None,
                method: None,
                destination: None,
                terminated: false,
                decision: &decision,
                latency_us: 0,
            };
            // Refused either way; a failed write is reported where the
            // recorder reports failures.
            if let Err(error) = recorder.record(&connection) {
                recorder.unrecorded(&error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::audit::RecordError;

    #[derive(Default)]
    struct Rows(Mutex<Vec<String>>);

    impl Recorder for Rows {
        fn record(&self, c: &Connection<'_>) -> Result<(), RecordError> {
            self.0.lock().unwrap().push(c.decision.reasons[0].clone());
            Ok(())
        }
    }

    #[test]
    fn a_thousand_bad_credentials_are_a_few_rows_that_count_them_all() {
        let noise = Noise::default();
        let rows = Rows::default();
        let refused = Decision::single(Verdict::Deny, RULE_SESSION, "wrong credential");
        let start = Instant::now();
        let mut written = Vec::new();
        for i in 0..1000u64 {
            let at = start + Duration::from_millis(i * 25);
            noise.flush(&rows, at);
            if let Some(row) = noise.row(Unauthenticated::Credential, &refused, at) {
                written.push(row);
            }
        }
        // 25 s of refusals: the first as it was, then one per interval.
        assert_eq!(written[0], refused);
        assert!(written.len() <= 3, "{written:?}");
        noise.flush(&rows, start + INTERVAL * 10);
        let mut total = 1;
        for row in written.iter().skip(1) {
            assert_eq!(row.rules, [RULE_SESSION]);
            assert!(
                row.reasons[0].ends_with("the last: wrong credential"),
                "{row:?}"
            );
            total += row.reasons[0]
                .split(' ')
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap();
        }
        for reason in rows.0.into_inner().unwrap() {
            total += reason.split(' ').next().unwrap().parse::<u64>().unwrap();
        }
        assert_eq!(total, 1000, "every refusal is counted");
    }

    #[test]
    fn a_bad_head_has_its_own_first_row() {
        let noise = Noise::default();
        let now = Instant::now();
        let credential = Decision::single(Verdict::Deny, RULE_SESSION, "wrong");
        let head = Decision::single(Verdict::Deny, RULE_REQUEST, "not HTTP");
        assert!(
            noise
                .row(Unauthenticated::Credential, &credential, now)
                .is_some()
        );
        assert_eq!(noise.row(Unauthenticated::Head, &head, now), Some(head));
    }
}

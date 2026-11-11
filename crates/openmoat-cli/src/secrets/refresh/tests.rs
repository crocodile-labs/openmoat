use std::time::{Duration, Instant};

use openmoat_core::Policy;
use openmoat_proxy::Broker;
use zeroize::Zeroizing;

use super::{Refresher, failed};
use crate::secrets::stand::Stand;

/// Generated stand-ins; no real secret is used anywhere in these tests.
const FIRST: &str = "fake-renewed-value-0";

/// A broker holding secret `t` with `FIRST`, its value due for renewal, and
/// a refresher running `body` for it.
fn renewing(stand: &Stand, body: &str) -> (Broker, Refresher) {
    let program = stand.shell(body);
    let policy = Policy::parse(
        "version: 1\nsecrets:\n  - id: t\n    host: api.example.com\n    header: X-Key\n    \
         source:\n      command: { run: [/usr/bin/fake], lifetime: 15m }\n",
    )
    .unwrap();
    let secret = policy.secrets[0].clone();
    let broker = Broker::new(vec![(secret, Zeroizing::new(FIRST.to_owned()))]).unwrap();
    let rotation = broker.rotation("t").unwrap();
    // Less left than `refresh_before` (3 minutes for 15): due now.
    rotation
        .renew(Zeroizing::new(FIRST.to_owned()), Duration::from_secs(60))
        .unwrap();
    let refresher = Refresher::new(
        vec![(program, rotation, Zeroizing::new(FIRST.to_owned()))],
        vec![Zeroizing::new("fake-fixed-value-1234".to_owned())],
    );
    (broker, refresher)
}

#[test]
fn a_due_value_is_renewed_and_both_values_are_masked() {
    let stand = Stand::new();
    let count = format!("{}/count", stand.root);
    let (broker, mut refresher) = renewing(
        &stand,
        &format!(
            "n=$(cat {count} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {count}\n\
             echo fake-renewed-value-$n"
        ),
    );
    let masks = refresher.masks();
    assert_eq!(refresher.tick(Instant::now()), Vec::<String>::new());
    let left = broker.rotation("t").unwrap().remaining().unwrap();
    assert!(left > Duration::from_secs(800), "{left:?}");
    // The audit writer takes up masks for the old value, the new one and the
    // fixed ones: none of them is ever written to the log.
    let known = masks.lock().unwrap().take().unwrap();
    for value in [FIRST, "fake-renewed-value-1", "fake-fixed-value-1234"] {
        assert_eq!(known.redact(&format!("x {value} y")), "x [redacted] y");
    }
    // Not due again: the program does not run.
    assert_eq!(refresher.tick(Instant::now()), Vec::<String>::new());
    assert_eq!(std::fs::read_to_string(&count).unwrap().trim(), "1");
    assert!(masks.lock().unwrap().is_none());
}

#[test]
fn a_failed_renewal_is_reported_without_output_and_retried_later() {
    let stand = Stand::new();
    let (broker, mut refresher) = renewing(&stand, "echo fake-printed-on-failure-99; exit 1");
    let now = Instant::now();
    let lines = refresher.tick(now);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("secret `t` was not renewed"),
        "{}",
        lines[0]
    );
    assert!(lines[0].contains("refused once it expires"), "{}", lines[0]);
    assert!(
        !lines[0].contains("fake-printed-on-failure"),
        "{}",
        lines[0]
    );
    // Not again until the retry time; the old value keeps its deadline.
    assert_eq!(refresher.tick(now), Vec::<String>::new());
    assert_eq!(refresher.tick(now + super::RETRY).len(), 1);
    let left = broker.rotation("t").unwrap().remaining().unwrap();
    assert!(left <= Duration::from_secs(60), "{left:?}");
    assert!(refresher.masks().lock().unwrap().is_none());
}

#[test]
fn the_failure_line_names_the_secret_and_the_reason() {
    let line = failed("t", &anyhow::Error::msg("x failed (exit status: 1)"));
    assert_eq!(
        line,
        "openmoat proxy: secret `t` was not renewed: x failed (exit status: 1); requests that \
         need it are refused once it expires"
    );
}

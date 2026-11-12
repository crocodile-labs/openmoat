use std::time::{Duration, Instant};

use openmoat_core::Policy;
use openmoat_proxy::Broker;
use zeroize::Zeroizing;

use super::{Refresher, failed};
use crate::secrets::command::Program;
use crate::secrets::stand::Stand;

/// Generated stand-ins; no real secret is used anywhere in these tests.
const FIRST: &str = "fake-renewed-value-0";

/// A broker holding secret `t` with `FIRST`, its value due for renewal, and
/// a refresher running `body` for it.
fn renewing(stand: &Stand, body: &str) -> (Broker, Refresher) {
    renewing_with(stand.shell(body))
}

/// [`renewing`] with a program the test made.
fn renewing_with(program: Program) -> (Broker, Refresher) {
    let policy = Policy::parse(
        "version: 1\nsecrets:\n  - id: t\n    host: api.example.com\n    header: X-Key\n    \
         source:\n      command: { run: [/usr/bin/fake], lifetime: 15m }\n",
    )
    .unwrap();
    let secret = policy.secrets[0].clone();
    let broker = Broker::new(vec![(secret, Zeroizing::new(FIRST.to_owned()))]).unwrap();
    let rotation = broker.rotation("t").unwrap();
    // Less left than twice the stand-in's time limit: due now.
    rotation
        .renew(Zeroizing::new(FIRST.to_owned()), Duration::from_secs(15))
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
    assert!(left <= Duration::from_secs(15), "{left:?}");
    assert!(refresher.masks().lock().unwrap().is_none());
}

/// A program that says its value lives an hour, for a source whose
/// `lifetime` is 12 hours: renewed a fifth of that hour before it ends,
/// about every 48 minutes, not on every look (the `refresh_before` of 12
/// hours, a fifth of `lifetime`, is longer than the value lives).
#[test]
fn renewal_follows_the_lifetime_the_value_got() {
    let stand = Stand::new();
    let count = format!("{}/count", stand.root);
    let mut source = Stand::source(&[
        "/bin/sh",
        "-c",
        &format!(
            "n=$(cat {count} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {count}\n\
             printf '{{\"value\": \"fake-hourly-value-%s\", \"expires_in\": 3600}}' $n"
        ),
    ]);
    source.lifetime = "12h".into();
    let (broker, mut refresher) = renewing_with(stand.shell_with(&source));
    let runs = || std::fs::read_to_string(&count).map_or(0, |n| n.trim().parse().unwrap());
    let now = Instant::now();
    assert_eq!(refresher.tick(now), Vec::<String>::new());
    assert_eq!(runs(), 1);
    let left = broker.rotation("t").unwrap().remaining().unwrap();
    assert!(left > Duration::from_secs(3590), "{left:?}");
    // Every two seconds for 47 minutes: not once.
    for secs in (2..47 * 60).step_by(2) {
        assert_eq!(
            refresher.tick(now + Duration::from_secs(secs)),
            Vec::<String>::new()
        );
    }
    assert_eq!(runs(), 1);
    // 48 minutes on, 12 before the hour ends: renewed.
    assert_eq!(
        refresher.tick(now + Duration::from_mins(48)),
        Vec::<String>::new()
    );
    assert_eq!(runs(), 2);
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

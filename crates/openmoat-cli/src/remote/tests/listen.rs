//! The listener when the channel or the audit log fails, and when a stranger writes.

use std::time::Duration;

use anyhow::Result;
use openmoat_core::Verdict;

use super::super::channel::Reply;
use super::super::gate::MAX_WAITING;
use super::super::listen::{Listener, Records, Row};
use super::{
    APPROVER, Fake, NOW, Rows, approve_button, call, gated, only_request, press, review, setup,
};

#[test]
fn a_channel_that_cannot_send_leaves_the_request_waiting() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let mut fake = Fake {
        fail_send: true,
        ..Fake::default()
    };
    let mut rows = Rows::default();
    let mut listener = Listener::new(&s.store, &s.key, s.settings.clone());
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW + 1)
        .unwrap();
    assert!(listener.log.iter().any(|l| l.contains("could not send")));
    fake.fail_send = false;
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW + 2)
        .unwrap();
    assert_eq!(fake.sent.len(), 1, "sent on the next round");
    assert_eq!(gated(&s, &req, review(), NOW + 3).verdict, Verdict::Review);
}

#[test]
fn too_many_waiting_requests_are_not_sent() {
    let s = setup();
    for n in 0..MAX_WAITING {
        gated(&s, &call("s1", &format!("npm publish {n}")), review(), NOW);
    }
    let d = gated(&s, &call("s1", "npm publish more"), review(), NOW);
    assert!(
        d.reasons.iter().any(|r| r.contains("already waiting")),
        "{d:?}"
    );
    assert_eq!(s.store.requests().unwrap().len(), MAX_WAITING);
}

#[test]
fn a_plain_message_from_a_stranger_names_their_id() {
    let s = setup();
    let mut fake = Fake::default();
    let mut rows = Rows::default();
    let mut listener = Listener::new(&s.store, &s.key, s.settings.clone());
    fake.queued.push_back(Reply {
        from: "777".to_owned(),
        name: "@new".to_owned(),
        button: None,
        handle: String::new(),
    });
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW)
        .unwrap();
    assert!(
        listener
            .log
            .iter()
            .any(|l| l.contains("openmoat approvals allow 777")),
        "{:?}",
        listener.log
    );
    assert_eq!(fake.settled.len(), 0, "a stranger gets no reply");
    assert_eq!(rows.0, Vec::<Row>::new());
}

#[test]
fn an_answer_that_cannot_be_recorded_does_not_stand() {
    struct Failing;
    impl Records for Failing {
        fn record(&mut self, _: Row) -> Result<()> {
            anyhow::bail!("audit log unavailable")
        }
    }
    let s = setup();
    gated(&s, &call("s1", "npm publish"), review(), NOW);
    let request = only_request(&s);
    let mut fake = Fake::default();
    let mut listener = Listener::new(&s.store, &s.key, s.settings.clone());
    fake.queued
        .push_back(press(APPROVER, &approve_button(&s, &request)));
    assert!(
        listener
            .step(&mut fake, &mut Failing, Duration::ZERO, &|| NOW + 1)
            .is_err()
    );
    assert!(s.store.answer(&request.id).is_none());
}

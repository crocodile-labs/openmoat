//! The listener when the channel or the audit log fails, and when a stranger writes.

use std::time::Duration;

use anyhow::Result;
use openmoat_core::Verdict;

use super::super::REFUSED_RULE;
use super::super::channel::Reply;
use super::super::gate::{MAX_WAITING, gate_used};
use super::super::listen::{Listener, Records, Row};
use super::{
    APPROVER, FAKE, Fake, NOW, Rows, approve_button, call, gated, only_request, press, review,
    setup,
};
use openmoat_audit::KnownSecrets;

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
    let mut listener = Listener::new(&s.store, &s.key, &FAKE, s.settings.clone());
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
    let mut listener = Listener::new(&s.store, &s.key, &FAKE, s.settings.clone());
    fake.queued.push_back(Reply {
        from: "777".to_owned(),
        name: "@new".to_owned(),
        text: Some("/start".to_owned()),
        ..Reply::default()
    });
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW)
        .unwrap();
    assert!(
        listener
            .log
            .iter()
            .any(|l| l.contains("openmoat approvals allow fake:777")),
        "{:?}",
        listener.log
    );
    assert_eq!(fake.settled.len(), 0, "a stranger gets no reply");
    assert_eq!(rows.0, Vec::<Row>::new());
}

/// An answer that cannot be recorded does not stand, and the rest of the
/// poll is still answered: one failing reply never drops the others, and
/// the channel moves past the poll only once every reply was handled.
#[test]
fn an_answer_that_cannot_be_recorded_does_not_stand() {
    /// The first row fails, as an audit log that is briefly unavailable.
    #[derive(Default)]
    struct FailsFirst(usize);
    impl Records for FailsFirst {
        fn record(&mut self, _: Row) -> Result<()> {
            self.0 += 1;
            if self.0 == 1 {
                anyhow::bail!("audit log unavailable")
            }
            Ok(())
        }
    }
    let s = setup();
    gated(&s, &call("s1", "npm publish"), review(), NOW);
    gated(&s, &call("s1", "npm test"), review(), NOW);
    let all: Vec<_> = s.store.requests().unwrap().into_iter().flatten().collect();
    assert_eq!(all.len(), 2);
    let mut fake = Fake::default();
    let mut records = FailsFirst::default();
    let mut listener = Listener::new(&s.store, &s.key, &FAKE, s.settings.clone());
    for request in &all {
        fake.queued
            .push_back(press(APPROVER, &approve_button(&s, request)));
    }
    listener
        .step(&mut fake, &mut records, Duration::ZERO, &|| NOW + 1)
        .unwrap();
    assert!(
        s.store.answer(&all[0].id).is_none(),
        "not recorded, so not applied"
    );
    assert!(
        s.store.answer(&all[1].id).is_some(),
        "the next reply still answered"
    );
    assert!(
        listener
            .log
            .iter()
            .any(|l| l.contains("could not be handled: audit log unavailable")),
        "{:?}",
        listener.log
    );
    assert_eq!(fake.handled, 1);
}

/// An approval the guard used for a call it then refused (its row could not
/// be written): the call stays denied, and the approver is told why and the
/// refusal recorded, once, instead of the approval vanishing without a word.
#[test]
fn an_approved_call_refused_after_all_is_told_to_the_approver() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let request = only_request(&s);
    let mut fake = Fake::default();
    let mut rows = Rows::default();
    let mut listener = Listener::new(&s.store, &s.key, &FAKE, s.settings.clone());
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW + 1)
        .unwrap();
    fake.queued
        .push_back(press(APPROVER, &approve_button(&s, &request)));
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW + 1)
        .unwrap();
    let (decision, approved) =
        gate_used(&s.store, &req, review(), &KnownSecrets::default(), NOW + 2);
    assert_eq!(decision.verdict, Verdict::Allow, "{decision:?}");
    let line = approved
        .expect("the approval was used")
        .refused("audit log unavailable: disk full");
    assert!(
        line.contains("was approved, but the call was refused: audit log unavailable: disk full"),
        "{line}"
    );
    assert!(line.contains("the approver is told"), "{line}");
    rows.0.clear();
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW + 3)
        .unwrap();
    let told: Vec<&String> = fake
        .notes
        .iter()
        .filter(|(to, _)| to == APPROVER)
        .map(|(_, text)| text)
        .collect();
    assert_eq!(told.len(), 1, "{:?}", fake.notes);
    assert!(
        told[0].contains("approved, but the call was refused: audit log unavailable"),
        "{told:?}"
    );
    assert_eq!(rows.0.len(), 1, "{:?}", rows.0);
    assert_eq!(rows.0[0].rule, REFUSED_RULE);
    assert_eq!(s.store.refused().len(), 0);
    // Once only.
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW + 4)
        .unwrap();
    assert_eq!(fake.notes.len(), 1);
    // A call that used no approval has none to report.
    let (_, none) = gate_used(
        &s.store,
        &call("s1", "ls"),
        review(),
        &KnownSecrets::default(),
        NOW + 5,
    );
    assert!(none.is_none());
}

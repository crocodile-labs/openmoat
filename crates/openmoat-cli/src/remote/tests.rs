//! Remote approval end to end against a fake channel: no network, no token.

use std::collections::VecDeque;
use std::time::Duration;

use anyhow::Result;
use openmoat_audit::KnownSecrets;
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::{HookRequest, Host};

use super::answer::{self, Answer};
use super::channel::{Channel, Prompt, Reply};
use super::listen::{Listener, Records, Row};
use super::request::Request;
use super::settings::{DEFAULT_EXPIRY_S, Settings};
use super::store::{DIR, Store};
use super::*;
use crate::proxy_session::Key;

mod text;

/// 2026-11-10 12:00:00 UTC.
const NOW: i64 = 1_794_312_000_000;
const APPROVER: &str = "4242";

/// A channel that records what it sent and hands out queued replies.
#[derive(Default)]
struct Fake {
    sent: Vec<(String, Prompt)>,
    notes: Vec<(String, String)>,
    settled: Vec<(Reply, String)>,
    queued: VecDeque<Reply>,
    fail_send: bool,
}

impl Channel for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }
    fn send(&mut self, to: &str, prompt: &Prompt) -> Result<()> {
        if self.fail_send {
            anyhow::bail!("channel down");
        }
        self.sent.push((to.to_owned(), prompt.clone()));
        Ok(())
    }
    fn notify(&mut self, to: &str, text: &str) -> Result<()> {
        self.notes.push((to.to_owned(), text.to_owned()));
        Ok(())
    }
    fn poll(&mut self, _: Duration) -> Result<Vec<Reply>> {
        Ok(self.queued.drain(..).collect())
    }
    fn settle(&mut self, reply: &Reply, text: &str) -> Result<()> {
        self.settled.push((reply.clone(), text.to_owned()));
        Ok(())
    }
}

#[derive(Default)]
struct Rows(Vec<Row>);

impl Records for Rows {
    fn record(&mut self, row: Row) -> Result<()> {
        self.0.push(row);
        Ok(())
    }
}

struct Setup {
    _dir: tempfile::TempDir,
    store: Store,
    key: Key,
    settings: Settings,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path().join(DIR));
    let key = Key::load_or_create_at(&store.key_path()).unwrap();
    let mut settings = Settings::new("fake", DEFAULT_EXPIRY_S).unwrap();
    settings.approvers.push(APPROVER.to_owned());
    settings.save(&store.settings_path(), &key).unwrap();
    Setup {
        _dir: dir,
        store,
        key,
        settings,
    }
}

fn call(session: &str, command: &str) -> HookRequest {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": session,
        "cwd": "/p",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    Host::ClaudeCode
        .parse_request(&payload.to_string())
        .unwrap()
}

fn review() -> Decision {
    Decision::single(Verdict::Review, "runs-later", "runs later")
}

fn gated(s: &Setup, request: &HookRequest, decision: Decision, now: i64) -> Decision {
    gate(&s.store, request, decision, &KnownSecrets::default(), now)
}

fn only_request(s: &Setup) -> Request {
    let all: Vec<Request> = s.store.requests().unwrap().into_iter().flatten().collect();
    assert_eq!(all.len(), 1, "{all:?}");
    all.into_iter().next().unwrap()
}

fn press(from: &str, data: &str) -> Reply {
    Reply {
        from: from.to_owned(),
        name: "someone".to_owned(),
        button: Some(data.to_owned()),
        handle: "cb".to_owned(),
    }
}

/// The listener's one round at `now`, with `replies` arriving.
fn listen(s: &Setup, fake: &mut Fake, rows: &mut Rows, replies: Vec<Reply>, now: i64) {
    let mut listener = Listener::new(&s.store, &s.key, s.settings.clone());
    // The listener sends first, then reads replies, as one round does.
    listener.step(fake, rows, Duration::ZERO, &|| now).unwrap();
    fake.queued.extend(replies);
    listener.step(fake, rows, Duration::ZERO, &|| now).unwrap();
}

fn approve_button(s: &Setup, request: &Request) -> String {
    answer::button(&s.key, answer::Verdict::Approve, request)
}

#[test]
fn a_review_is_sent_approved_and_runs_once() {
    let s = setup();
    let req = call("s1", "npm publish");
    let first = gated(&s, &req, review(), NOW);
    assert_eq!(first.verdict, Verdict::Review);
    assert!(
        first
            .reasons
            .iter()
            .any(|r| r.contains("sent for approval over fake")),
        "{first:?}"
    );
    let request = only_request(&s);
    // A second try before an answer waits on the same request.
    let again = gated(&s, &req, review(), NOW + 1);
    assert!(
        again
            .reasons
            .iter()
            .any(|r| r.contains("waiting for approval"))
    );
    assert_eq!(only_request(&s).id, request.id);

    let mut fake = Fake::default();
    let mut rows = Rows::default();
    let button = approve_button(&s, &request);
    listen(
        &s,
        &mut fake,
        &mut rows,
        vec![press(APPROVER, &button)],
        NOW + 2,
    );
    assert_eq!(fake.sent.len(), 1, "sent once, to the one approver");
    assert_eq!(fake.sent[0].0, APPROVER);
    assert_eq!(rows.0.len(), 1);
    assert_eq!(rows.0[0].rule, APPROVED_ROW_RULE);
    assert_eq!(rows.0[0].session, "s1");

    let allowed = gated(&s, &req, review(), NOW + 3);
    assert_eq!(allowed.verdict, Verdict::Allow, "{allowed:?}");
    assert_eq!(allowed.rules, [APPROVED_RULE]);
    // Used: the next identical call is a new request, not an allow.
    let next = gated(&s, &req, review(), NOW + 4);
    assert_eq!(next.verdict, Verdict::Review);
    assert_ne!(only_request(&s).id, request.id);
}

#[test]
fn an_approval_is_used_once() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let request = only_request(&s);
    let answer = Answer::signed(
        &s.key,
        &request,
        (answer::Verdict::Approve, APPROVER, "fake"),
        NOW,
    )
    .unwrap();
    assert!(s.store.put_answer(&answer).unwrap());
    // Another guard won the race: the marker is there first.
    assert!(s.store.use_once(&request.id).unwrap());
    let raced = gated(&s, &req, review(), NOW + 1);
    assert_eq!(raced.verdict, Verdict::Review, "{raced:?}");
    assert!(!s.store.use_once(&request.id).unwrap());
}

#[test]
fn a_restored_answer_is_not_used_again() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let request = only_request(&s);
    let answer = Answer::signed(
        &s.key,
        &request,
        (answer::Verdict::Approve, APPROVER, "fake"),
        NOW,
    )
    .unwrap();
    s.store.put_answer(&answer).unwrap();
    assert_eq!(gated(&s, &req, review(), NOW + 1).verdict, Verdict::Allow);
    // Request and answer put back, as from a backup.
    s.store.put_request(&request).unwrap();
    s.store.put_answer(&answer).unwrap();
    let replayed = gated(&s, &req, review(), NOW + 2);
    assert_eq!(replayed.verdict, Verdict::Review, "{replayed:?}");
}

#[test]
fn an_approval_answers_only_its_own_call() {
    let s = setup();
    gated(&s, &call("s1", "npm publish"), review(), NOW);
    let request = only_request(&s);
    let answer = Answer::signed(
        &s.key,
        &request,
        (answer::Verdict::Approve, APPROVER, "fake"),
        NOW,
    )
    .unwrap();
    s.store.put_answer(&answer).unwrap();
    for (other, decision) in [
        (call("s1", "npm publish --tag x"), review()),
        (call("s2", "npm publish"), review()),
        (
            call("s1", "npm publish"),
            Decision::single(Verdict::Review, "other-rule", "another rule"),
        ),
    ] {
        let d = gated(&s, &other, decision, NOW + 1);
        assert_eq!(d.verdict, Verdict::Review, "{other:?}: {d:?}");
    }
    // A content change of the same write is another call too.
    let write = |content: &str| {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse", "session_id": "s1", "cwd": "/p",
            "tool_name": "Write",
            "tool_input": { "file_path": "/p/a.sh", "content": content },
        });
        Host::ClaudeCode
            .parse_request(&payload.to_string())
            .unwrap()
    };
    let digest =
        |r: &HookRequest| request::digest(r, r.action.as_ref().unwrap(), &review()).unwrap();
    assert_ne!(digest(&write("echo a")), digest(&write("rm -rf ~")));
    assert_eq!(digest(&write("echo a")), digest(&write("echo a")));
}

#[test]
fn only_a_review_is_sent() {
    let s = setup();
    let req = call("s1", "cat ~/.ssh/id_rsa");
    for verdict in [Verdict::Deny, Verdict::Allow, Verdict::Defer] {
        let decision = Decision::single(verdict, "secrets-paths", "x");
        let d = gated(&s, &req, decision.clone(), NOW);
        assert_eq!(d, decision);
    }
    assert_eq!(s.store.requests().unwrap().len(), 0);
}

#[test]
fn an_answer_from_someone_not_allowed_is_refused() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let request = only_request(&s);
    let mut fake = Fake::default();
    let mut rows = Rows::default();
    let button = approve_button(&s, &request);
    listen(
        &s,
        &mut fake,
        &mut rows,
        vec![press("666", &button)],
        NOW + 1,
    );
    assert_eq!(rows.0.len(), 1);
    assert_eq!(rows.0[0].rule, REFUSED_RULE);
    assert!(fake.settled[0].1.contains("not an approver"));
    assert!(s.store.answer(&request.id).is_none());
    assert_eq!(gated(&s, &req, review(), NOW + 2).verdict, Verdict::Review);
    // An answer file naming someone the person never allowed is not used either.
    let forged = Answer::signed(
        &s.key,
        &request,
        (answer::Verdict::Approve, "666", "fake"),
        NOW,
    )
    .unwrap();
    s.store.put_answer(&forged).unwrap();
    assert_eq!(gated(&s, &req, review(), NOW + 3).verdict, Verdict::Review);
}

#[test]
fn a_button_that_was_not_sent_is_refused() {
    let s = setup();
    gated(&s, &call("s1", "npm publish"), review(), NOW);
    let request = only_request(&s);
    let mut fake = Fake::default();
    let mut rows = Rows::default();
    let forged = format!("a.{}.0000000000000000", request.id);
    listen(
        &s,
        &mut fake,
        &mut rows,
        vec![press(APPROVER, &forged)],
        NOW + 1,
    );
    assert_eq!(rows.0[0].rule, REFUSED_RULE);
    assert!(s.store.answer(&request.id).is_none());
    // The deny button's tag does not approve.
    let deny = answer::button(&s.key, answer::Verdict::Deny, &request);
    let swapped = deny.replacen("d.", "a.", 1);
    listen(
        &s,
        &mut fake,
        &mut rows,
        vec![press(APPROVER, &swapped)],
        NOW + 2,
    );
    assert!(s.store.answer(&request.id).is_none());
}

#[test]
fn an_answer_signed_with_another_key_is_refused() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let request = only_request(&s);
    let other_dir = tempfile::tempdir().unwrap();
    let other = Key::load_or_create_at(&other_dir.path().join("k")).unwrap();
    let forged = Answer::signed(
        &other,
        &request,
        (answer::Verdict::Approve, APPROVER, "fake"),
        NOW,
    )
    .unwrap();
    s.store.put_answer(&forged).unwrap();
    assert_eq!(gated(&s, &req, review(), NOW + 1).verdict, Verdict::Review);
    // A request written without the key is never sent; the listener removes it.
    let mut planted = request.clone();
    planted.id = "0".repeat(32);
    planted.sign(&other).unwrap();
    s.store.put_request(&planted).unwrap();
    let mut fake = Fake::default();
    let mut rows = Rows::default();
    listen(&s, &mut fake, &mut rows, Vec::new(), NOW + 2);
    assert!(
        fake.sent
            .iter()
            .all(|(_, p)| !p.approve.contains(&planted.id))
    );
    assert!(rows.0.iter().any(|r| r.rule == REFUSED_RULE));
    assert!(s.store.request(&planted.id).is_none());
}

#[test]
fn an_expired_request_is_not_approved() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let request = only_request(&s);
    let late = request.expires_ms + 1;
    let mut fake = Fake::default();
    let mut rows = Rows::default();
    let button = approve_button(&s, &request);
    // Sent while fresh, pressed after it expired.
    let mut listener = Listener::new(&s.store, &s.key, s.settings.clone());
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| NOW + 1)
        .unwrap();
    fake.queued.push_back(press(APPROVER, &button));
    listener
        .step(&mut fake, &mut rows, Duration::ZERO, &|| late)
        .unwrap();
    assert!(
        rows.0.iter().any(|r| r.rule == EXPIRED_RULE),
        "{:?}",
        rows.0
    );
    assert!(s.store.answer(&request.id).is_none());
    assert!(fake.notes.iter().any(|(_, t)| t.contains("expired")));
    // An answer written in time is still not used once the request expired.
    s.store.put_request(&request).unwrap();
    let answer = Answer::signed(
        &s.key,
        &request,
        (answer::Verdict::Approve, APPROVER, "fake"),
        NOW,
    )
    .unwrap();
    s.store.put_answer(&answer).unwrap();
    let d = gated(&s, &req, review(), late);
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
}

#[test]
fn a_remote_deny_holds_until_the_request_expires() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let request = only_request(&s);
    let mut fake = Fake::default();
    let mut rows = Rows::default();
    let deny = answer::button(&s.key, answer::Verdict::Deny, &request);
    listen(
        &s,
        &mut fake,
        &mut rows,
        vec![press(APPROVER, &deny)],
        NOW + 1,
    );
    assert_eq!(rows.0[0].rule, DENIED_RULE);
    let d = gated(&s, &req, review(), NOW + 2);
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, [DENIED_RULE]);
    let after = gated(&s, &req, review(), request.expires_ms + 1);
    assert_eq!(after.verdict, Verdict::Review);
}

#[test]
fn tampered_settings_are_refused() {
    let s = setup();
    let req = call("s1", "npm publish");
    gated(&s, &req, review(), NOW);
    let request = only_request(&s);
    let answer = Answer::signed(
        &s.key,
        &request,
        (answer::Verdict::Approve, "666", "fake"),
        NOW,
    )
    .unwrap();
    s.store.put_answer(&answer).unwrap();
    // `666` added to the list by hand, without the key.
    let path = s.store.settings_path();
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("\"4242\"", "\"4242\", \"666\"")).unwrap();
    assert!(Settings::load(&path, &s.key).is_err());
    let d = gated(&s, &req, review(), NOW + 1);
    assert_eq!(d.verdict, Verdict::Review);
    assert!(d.reasons.iter().any(|r| r.contains("not signed")), "{d:?}");
}

#[test]
fn without_a_key_the_review_stays() {
    let s = setup();
    std::fs::remove_file(s.store.key_path()).unwrap();
    let d = gated(&s, &call("s1", "npm publish"), review(), NOW);
    assert_eq!(d.verdict, Verdict::Review);
    assert!(
        d.reasons
            .iter()
            .any(|r| r.contains("not sent for remote approval"))
    );
    // And with no channel at all, the decision is untouched.
    let none = tempfile::tempdir().unwrap();
    let store = Store::at(none.path().join(DIR));
    let d = gate(
        &store,
        &call("s1", "npm publish"),
        review(),
        &KnownSecrets::default(),
        NOW,
    );
    assert_eq!(d, review());
}

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
    for n in 0..gate::MAX_WAITING {
        gated(&s, &call("s1", &format!("npm publish {n}")), review(), NOW);
    }
    let d = gated(&s, &call("s1", "npm publish more"), review(), NOW);
    assert!(
        d.reasons.iter().any(|r| r.contains("already waiting")),
        "{d:?}"
    );
    assert_eq!(s.store.requests().unwrap().len(), gate::MAX_WAITING);
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

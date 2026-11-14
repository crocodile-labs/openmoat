//! The two halves of `listen` on their own threads (ADR-093): a request is
//! sent within about a second of the guard writing it, the beat is kept and
//! removed at the end, and a long poll answers the moment a reply arrives.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use openmoat_audit::KnownSecrets;

use super::super::channel::{Capabilities, Channel, Options, Prompt, Reply, Secrets, Spec};
use super::super::gate::gate_used;
use super::super::listen::Listener;
use super::super::listen::run::{self, Shared};
use super::super::live;
use super::super::settings::Settings;
use super::super::wait::Hold;
use super::{APPROVER, Rows, Setup, approve_button, call, only_request, press, review, setup};

/// A channel whose poll waits on its "server" up to the poll's time, and
/// returns the moment a reply is queued, as a long poll does.
static LONG: Spec = Spec {
    name: "fake",
    title: "Fake",
    capabilities: Capabilities {
        buttons: true,
        button_bytes: 64,
        max_text: 4096,
        poll_wait: Duration::from_secs(10),
    },
    fields: &[],
    user_id: "a number",
    valid_user: |id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
    open: |_: &Secrets, _: &Options| Ok(Box::new(Watched::default())),
    next_steps: |_| String::new(),
    revoke: "",
};

#[derive(Clone, Default)]
struct Watched {
    sent: Arc<Mutex<Vec<String>>>,
    inbox: Arc<(Mutex<VecDeque<Reply>>, Condvar)>,
}

impl Watched {
    fn queue(&self, reply: Reply) {
        let (queue, ready) = &*self.inbox;
        queue.lock().unwrap().push_back(reply);
        ready.notify_all();
    }
}

impl Channel for Watched {
    fn account(&mut self) -> Result<String> {
        Ok("@fake".to_owned())
    }
    fn send(&mut self, to: &str, _: &Prompt) -> Result<()> {
        self.sent.lock().unwrap().push(to.to_owned());
        Ok(())
    }
    fn notify(&mut self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
    fn poll(&mut self, wait: Duration) -> Result<Vec<Reply>> {
        let (queue, ready) = &*self.inbox;
        let queue = queue.lock().unwrap();
        let (mut queue, _) = ready
            .wait_timeout_while(queue, wait, |q| q.is_empty())
            .unwrap();
        Ok(queue.drain(..).collect())
    }
    fn settle(&mut self, _: &Reply, _: &str) -> Result<()> {
        Ok(())
    }
}

fn hold_a_call(s: &Setup) {
    gate_used(
        &s.store,
        &call("s1", "npm publish"),
        review(),
        &KnownSecrets::default(),
        (crate::time::now_ms(), &Hold::NONE),
    );
}

fn refresh(s: &Setup) -> impl Fn() -> Result<Settings> + '_ {
    || Settings::load(&s.store.settings_path(), &s.key)
}

fn until(what: &str, limit: Duration, done: impl Fn() -> bool) -> Duration {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < limit, "{what} not within {limit:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
    started.elapsed()
}

#[test]
fn a_new_request_is_sent_within_a_second_and_the_beat_is_kept_then_removed() {
    let s = setup();
    let shared = Shared::new(Arc::new(AtomicBool::new(false)));
    let channel = Watched::default();
    let sent = Arc::clone(&channel.sent);
    std::thread::scope(|scope| {
        let sending = scope.spawn(|| {
            let mut listener = Listener::new(&s.store, &s.key, &LONG, s.settings.clone());
            let mut channel = channel.clone();
            run::sending(
                &mut listener,
                (&mut channel, &mut Rows::default()),
                &shared,
                &refresh(&s),
                &|_| {},
            )
        });
        until("the first beat", Duration::from_secs(2), || {
            live::live(&s.store, &s.key, "fake", crate::time::now_ms())
        });
        hold_a_call(&s);
        let took = until("the send", Duration::from_secs(3), || {
            !sent.lock().unwrap().is_empty()
        });
        assert!(
            took <= run::SEND_EVERY + Duration::from_millis(500),
            "{took:?}"
        );
        assert_eq!(*sent.lock().unwrap(), [APPROVER]);
        shared.stop.store(true, Ordering::Relaxed);
        sending.join().unwrap().unwrap();
    });
    assert!(
        !live::live(&s.store, &s.key, "fake", crate::time::now_ms()),
        "the beat is removed when listen stops"
    );
}

#[test]
fn a_long_poll_answers_the_moment_a_reply_arrives() {
    let s = setup();
    hold_a_call(&s);
    let request = only_request(&s);
    let shared = Shared::new(Arc::new(AtomicBool::new(false)));
    let channel = Watched::default();
    std::thread::scope(|scope| {
        let answering = scope.spawn(|| {
            let mut listener = Listener::new(&s.store, &s.key, &LONG, s.settings.clone());
            let mut channel = channel.clone();
            run::answering(
                &mut listener,
                (&mut channel, &mut Rows::default()),
                &shared,
                &refresh(&s),
                &|_| {},
            );
        });
        std::thread::sleep(Duration::from_millis(200));
        channel.queue(press(APPROVER, &approve_button(&s, &request)));
        // Far sooner than the 10 s the poll may wait.
        let took = until("the answer", Duration::from_secs(5), || {
            s.store.has_answer(&request.id)
        });
        assert!(took < Duration::from_secs(2), "{took:?}");
        shared.stop.store(true, Ordering::Relaxed);
        // Something arrives, ending the poll; stopped, it is left unhandled.
        channel.queue(Reply::default());
        answering.join().unwrap();
    });
}

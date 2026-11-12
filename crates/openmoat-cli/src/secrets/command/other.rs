//! Reading a `command` source's answer where there are no process groups
//! (Windows): on a thread, with the program killed at the time limit. A
//! process it started and left holding its output keeps that thread waiting
//! until it ends (LIMITS.md).

use std::io::Read as _;
use std::process::Child;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{MAX_OUTPUT, Outcome};

/// `child`'s output and how it ended, within `limit`.
pub(super) fn collect(child: &mut Child, limit: Duration) -> Outcome {
    let outcome = read_and_wait(child, limit);
    let _ = child.kill();
    let _ = child.wait();
    outcome
}

fn read_and_wait(child: &mut Child, limit: Duration) -> Outcome {
    let Some(mut stdout) = child.stdout.take() else {
        return Outcome::Broken(std::io::Error::other("no output pipe"));
    };
    let started = Instant::now();
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_OUTPUT + 1));
        let read = (&mut stdout)
            .take(MAX_OUTPUT as u64 + 1)
            .read_to_end(&mut out);
        let _ = send.send(read.map(|_| out));
    });
    let out = match receive.recv_timeout(limit) {
        Ok(Ok(out)) if out.len() > MAX_OUTPUT => return Outcome::TooMuch,
        Ok(Ok(out)) => out,
        Ok(Err(e)) => return Outcome::Broken(e),
        Err(_) => return Outcome::Late,
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Outcome::Done(status, out),
            Ok(None) if started.elapsed() < limit => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => return Outcome::Late,
            Err(e) => return Outcome::Broken(e),
        }
    }
}

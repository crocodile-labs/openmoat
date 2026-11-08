//! Relaying bytes both ways once a connection is allowed.
//!
//! One thread per direction. Each read waits at most the idle timeout; when it
//! expires the connection closes unless the other direction moved bytes in the
//! meantime, so a long download with a silent client is not cut off.
//!
//! The client's bytes can pass an inspection first. It can let a chunk
//! through, let only its start through and nothing from the client after it
//! (the end of a plain-HTTP request's body), or close the connection before
//! the chunk is forwarded. The upstream's bytes can pass an [`Answer`] that
//! holds some back and closes the connection before a brokered value.
//!
//! A [`Recheck`] asks, at most once per its interval and between reads,
//! whether the connection may stay open (a session whose taint grew); a
//! `false` closes it. Reads then wait at most that interval, so the question
//! is asked on a silent connection too.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const BUFFER: usize = 16 * 1024;

/// What happens to a chunk from the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Forward {
    /// Forward all of it.
    All,
    /// Forward its first `n` bytes; the client's later bytes are read (so the
    /// upstream's answer still flows back) and dropped.
    Part(usize),
    /// Close the connection without forwarding it.
    Stop,
}

/// What a chunk from the client passes before it is forwarded.
pub(crate) type Inspect<'a> = &'a mut dyn FnMut(&[u8]) -> Forward;

/// What the upstream's bytes pass before they reach the client, where the
/// answer must be searched (a plain-HTTP request a secret's value went into):
/// it may hold some back until it knows they start no value.
pub(crate) trait Answer: Send {
    /// The bytes to send on now, after `chunk` came; `None` closes the
    /// connection without sending anything more.
    fn pass(&mut self, chunk: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>>;
    /// The upstream finished: what is still held back, already searched.
    fn end(&mut self) -> zeroize::Zeroizing<Vec<u8>>;
}

/// Whether an open connection may stay open, asked every `every`.
#[derive(Clone, Copy)]
pub(crate) struct Recheck<'a> {
    /// The longest time between two questions.
    pub(crate) every: Duration,
    /// `false` closes the connection; it is not asked again.
    pub(crate) still_allowed: &'a (dyn Fn() -> bool + Sync),
}

/// Relay between `client` and `upstream` until both sides finish, the
/// connection is idle for `idle`, or `recheck` says it may not stay open.
/// The client's bytes pass `inspect`, the upstream's `answer`.
pub(crate) fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    idle: Duration,
    (inspect, answer): (Option<Inspect<'_>>, Option<&mut dyn Answer>),
    recheck: Option<Recheck<'_>>,
) {
    let wait = recheck.map_or(idle, |r| r.every.min(idle));
    for s in [client, upstream] {
        // A socket without timeouts could hold its thread forever.
        if s.set_read_timeout(Some(wait)).is_err() || s.set_write_timeout(Some(idle)).is_err() {
            close(client, upstream);
            return;
        }
    }
    let activity = Activity::new();
    let checks = Checks::new(recheck);
    thread::scope(|scope| {
        // A thread that cannot be created (the process is at its limit) closes
        // this connection instead of panicking through the server.
        let back = thread::Builder::new().spawn_scoped(scope, || {
            copy(upstream, client, &activity, &checks, idle, None, answer);
        });
        if back.is_err() {
            close(client, upstream);
            return;
        }
        copy(client, upstream, &activity, &checks, idle, inspect, None);
    });
}

/// Copy `from` to `to`: the client's bytes through `inspect`, the
/// upstream's through `answer`.
fn copy(
    from: &TcpStream,
    to: &TcpStream,
    activity: &Activity,
    checks: &Checks<'_>,
    idle: Duration,
    mut inspect: Option<Inspect<'_>>,
    mut answer: Option<&mut dyn Answer>,
) {
    let mut buf = [0u8; BUFFER];
    // Set once `Forward::Part` has been answered: nothing more is forwarded.
    let mut dropping = false;
    loop {
        let read = (&*from).read(&mut buf);
        if !checks.still_allowed(activity) {
            break;
        }
        match read {
            Ok(0) => {
                // What the answer held back was searched with all before it.
                if let Some(answer) = answer.as_mut()
                    && (&*to).write_all(&answer.end()).is_err()
                {
                    break;
                }
                // Half-close: the other direction may still be answering.
                let _ = to.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) if answer.is_some() => {
                let Some(out) = answer.as_mut().and_then(|a| a.pass(&buf[..n])) else {
                    break;
                };
                if (&*to).write_all(&out).is_err() {
                    break;
                }
                activity.touch();
            }
            // Dropped bytes do not count as activity. Intended: once the
            // request ends, only the upstream's answer keeps the connection
            // open, so an upstream silent for `idle` is closed even while the
            // client keeps sending; a client cannot hold it open by trickling.
            Ok(_) if dropping => {}
            Ok(n) => {
                let forward = inspect
                    .as_mut()
                    .map_or(Forward::All, |pass| pass(&buf[..n]));
                let send = match forward {
                    Forward::All => n,
                    Forward::Part(k) => {
                        dropping = true;
                        k.min(n)
                    }
                    Forward::Stop => break,
                };
                if (&*to).write_all(&buf[..send]).is_err() {
                    break;
                }
                activity.touch();
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e)
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                    && activity.idle_for() < idle => {}
            Err(_) => break,
        }
    }
    close(from, to);
}

fn close(a: &TcpStream, b: &TcpStream) {
    let _ = a.shutdown(Shutdown::Both);
    let _ = b.shutdown(Shutdown::Both);
}

/// The [`Recheck`] of one connection, shared by both directions: whichever
/// reads first after the interval asks, once.
struct Checks<'a> {
    recheck: Option<Recheck<'a>>,
    /// When the question was last asked, in ms since the relay started.
    last_ms: AtomicU64,
    refused: AtomicBool,
}

impl<'a> Checks<'a> {
    fn new(recheck: Option<Recheck<'a>>) -> Self {
        Self {
            recheck,
            last_ms: AtomicU64::new(0),
            refused: AtomicBool::new(false),
        }
    }

    fn still_allowed(&self, activity: &Activity) -> bool {
        let Some(recheck) = self.recheck else {
            return true;
        };
        if self.refused.load(Ordering::Acquire) {
            return false;
        }
        let now = activity.now_ms();
        let last = self.last_ms.load(Ordering::Acquire);
        let every = u64::try_from(recheck.every.as_millis()).unwrap_or(u64::MAX);
        let due = now.saturating_sub(last) >= every;
        // Only the direction that moves `last_ms` forward asks.
        if due
            && self
                .last_ms
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            && !(recheck.still_allowed)()
        {
            self.refused.store(true, Ordering::Release);
            return false;
        }
        true
    }
}

/// When either direction last moved bytes.
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        Duration::from_millis(
            self.now_ms()
                .saturating_sub(self.last_ms.load(Ordering::Relaxed)),
        )
    }
}

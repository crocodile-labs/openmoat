//! Relaying bytes both ways once a connection is allowed.
//!
//! One thread per direction. Each read waits at most the idle timeout; when it
//! expires the connection closes unless the other direction moved bytes in the
//! meantime, so a long download with a silent client is not cut off.
//!
//! The client's bytes can pass an inspection first. It can let a chunk
//! through, let only its start through and nothing from the client after it
//! (the end of a plain-HTTP request's body), or close the connection before
//! the chunk is forwarded.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Relay between `client` and `upstream` until both sides finish or the
/// connection is idle for `idle`.
pub(crate) fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    idle: Duration,
    inspect: Option<Inspect<'_>>,
) {
    for s in [client, upstream] {
        // A socket without timeouts could hold its thread forever.
        if s.set_read_timeout(Some(idle)).is_err() || s.set_write_timeout(Some(idle)).is_err() {
            close(client, upstream);
            return;
        }
    }
    let activity = Activity::new();
    thread::scope(|scope| {
        scope.spawn(|| copy(upstream, client, &activity, idle, None));
        copy(client, upstream, &activity, idle, inspect);
    });
}

fn copy(
    from: &TcpStream,
    to: &TcpStream,
    activity: &Activity,
    idle: Duration,
    mut inspect: Option<Inspect<'_>>,
) {
    let mut buf = [0u8; BUFFER];
    // Set once `Forward::Part` has been answered: nothing more is forwarded.
    let mut dropping = false;
    loop {
        match (&*from).read(&mut buf) {
            Ok(0) => {
                // Half-close: the other direction may still be answering.
                let _ = to.shutdown(Shutdown::Write);
                return;
            }
            // Dropped bytes do not count as activity.
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

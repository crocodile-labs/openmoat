//! Reading a `command` source's answer on Unix: on this thread, with a
//! deadline, and ending the program's whole process group afterwards, so
//! nothing it started outlives the run, and no thread waits on a pipe that a
//! child it left behind holds open.

use std::io::Read as _;
use std::process::Child;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process_group};
use zeroize::Zeroizing;

use super::{MAX_OUTPUT, Outcome};

/// How much is read at a time.
const CHUNK: usize = 8 * 1024;
/// The longest one wait for output: under any platform's limit on `poll`.
const LONGEST_WAIT: Duration = Duration::from_secs(1);

/// `child`'s output and how it ended, within `limit`. The program runs in a
/// process group of its own (`process_group(0)`), which is ended here
/// whatever happened.
pub(super) fn collect(child: &mut Child, limit: Duration) -> Outcome {
    let outcome = read_and_wait(child, Instant::now() + limit);
    // Its group's id is its process id. Killed before the program is reaped
    // when it is still running; after, the id cannot name another group
    // while any process of this one is left.
    let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
    outcome
}

fn read_and_wait(child: &mut Child, deadline: Instant) -> Outcome {
    let Some(mut stdout) = child.stdout.take() else {
        return Outcome::Broken(std::io::Error::other("no output pipe"));
    };
    // Room for all it may print, so the value is never left behind in a
    // freed buffer that is not zeroed.
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_OUTPUT + CHUNK));
    let mut chunk = Zeroizing::new([0_u8; CHUNK]);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Outcome::Late;
        }
        let Ok(wait) = Timespec::try_from(left.min(LONGEST_WAIT)) else {
            return Outcome::Late;
        };
        let ready = {
            let mut fds = [PollFd::new(&stdout, PollFlags::IN)];
            poll(&mut fds, Some(&wait))
        };
        match ready {
            Ok(0) | Err(Errno::INTR) => continue,
            Ok(_) => {}
            Err(e) => return Outcome::Broken(e.into()),
        }
        match stdout.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&chunk[..n]);
                if out.len() > MAX_OUTPUT {
                    return Outcome::TooMuch;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Outcome::Broken(e),
        }
    }
    drop(stdout);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Outcome::Done(status, out),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => return Outcome::Late,
            Err(e) => return Outcome::Broken(e),
        }
    }
}

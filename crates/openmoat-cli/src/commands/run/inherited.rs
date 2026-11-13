//! The open files `openmoat run` inherited from whatever started it (a shell, an
//! IDE, a CI runner) stay out of the sandbox (ADR-088). A descriptor the
//! launcher left open without close-on-exec would otherwise pass to the agent
//! through every `exec`, and neither Landlock nor Seatbelt checks a file that
//! is already open: a descriptor on `~/.ssh/id_rsa` reads it whatever the
//! policy denies. Rust's standard library marks close-on-exec only the
//! descriptors it creates, never the ones the process started with.
//!
//! So before the sandboxed program starts, every descriptor from 3 up is
//! marked close-on-exec; standard input, output and error (0–2) stay. OpenMoat
//! itself keeps using them: the flag only matters at `exec`.
//!
//! Descriptors passed to the sandbox on purpose: none. The proxy and the guard
//! relay are reached by address (the environment names them), bubblewrap gets
//! every argument on its command line and `sandbox-exec` its profile with `-p`;
//! the standard library connects 0–2 itself. A descriptor added later must be
//! named here and left out of the sweep.
//!
//! A sweep that cannot be completed refuses the run: the agent is not started
//! with descriptors OpenMoat could not check.

use std::io;
use std::os::fd::RawFd;

use anyhow::{Context as _, Result};

/// The first descriptor after standard input, output and error.
const FIRST: RawFd = 3;

/// Where the process's open descriptors are listed: Linux's `/proc` first,
/// then `/dev/fd`, which macOS has (and Linux links to `/proc/self/fd`).
const LISTS: [&str; 2] = ["/proc/self/fd", "/dev/fd"];

/// Mark every descriptor from 3 up close-on-exec, or say why it could not be
/// done. Called right before the sandboxed program (or bubblewrap) starts.
pub fn close_on_exec() -> Result<()> {
    // Linux 5.11 and later in one call. An older kernel answers ENOSYS or
    // EINVAL, and a container's seccomp profile may answer EPERM: walk then.
    if close_range() {
        return Ok(());
    }
    let mut failed = Vec::new();
    for list in LISTS {
        match walk(list) {
            Ok(()) => return Ok(()),
            Err(error) => failed.push(format!("{list}: {error}")),
        }
    }
    Err(io::Error::other(failed.join("; "))).context(
        "cannot keep the files OpenMoat was started with from the agent (marking them \
         close-on-exec); refusing to start it",
    )
}

/// `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`: whether the kernel did it.
#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "the C library has no safe wrapper, nor rustix: one raw system call"
)]
fn close_range() -> bool {
    // SAFETY: integer arguments only, no pointer. With CLOSE_RANGE_CLOEXEC the
    // call closes nothing; it sets a flag on descriptors, so no `OwnedFd` or
    // `File` anywhere in this process is invalidated.
    let done = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            FIRST.unsigned_abs(),
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    done == 0
}

/// None on macOS: the walk does it.
#[cfg(not(target_os = "linux"))]
fn close_range() -> bool {
    false
}

/// Mark each descriptor from 3 up that `list` names. The listing's own
/// descriptor is in it and closed by the time it is marked: `EBADF` is
/// skipped, as for any descriptor another thread closed meanwhile (a closed
/// descriptor cannot reach the agent). Any other failure is an error.
fn walk(list: &str) -> io::Result<()> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(list)? {
        let name = entry?.file_name();
        let fd: RawFd = name.to_str().and_then(|n| n.parse().ok()).ok_or_else(|| {
            io::Error::other(format!("{} is not a descriptor", name.to_string_lossy()))
        })?;
        if fd >= FIRST {
            found.push(fd);
        }
    }
    for fd in found {
        match mark(fd) {
            Err(error) if error.raw_os_error() == Some(libc::EBADF) => {}
            other => other?,
        }
    }
    Ok(())
}

/// Set close-on-exec on `fd`, keeping its other flags.
#[expect(
    unsafe_code,
    reason = "`fcntl` on a descriptor number this process does not own as an `OwnedFd`"
)]
fn mark(fd: RawFd) -> io::Result<()> {
    // SAFETY: `F_GETFD` and `F_SETFD` take and return integers and read no
    // memory. On a descriptor that is closed they fail with EBADF; on one
    // another thread reopened under the same number they set the flag on that
    // one, which only keeps it from the agent too.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC != 0 {
        return Ok(());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::{AsRawFd as _, RawFd};

    use super::{FIRST, LISTS, close_on_exec, walk};

    const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

    /// The descriptor flags of `fd`.
    #[expect(unsafe_code, reason = "the test reads the flag itself")]
    fn flags(fd: RawFd) -> i32 {
        // SAFETY: integers only; on a closed descriptor this is -1.
        unsafe { libc::fcntl(fd, libc::F_GETFD) }
    }

    /// `file`, inheritable as a launcher would leave it.
    #[expect(unsafe_code, reason = "the test clears the flag itself")]
    fn inheritable(file: &File) -> RawFd {
        let fd = file.as_raw_fd();
        // SAFETY: integers only, on a descriptor `file` owns.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
        assert_eq!(flags(fd) & libc::FD_CLOEXEC, 0);
        fd
    }

    #[test]
    fn the_sweep_marks_an_inherited_descriptor_close_on_exec() {
        let file = File::open(MANIFEST).unwrap();
        let fd = inheritable(&file);
        close_on_exec().unwrap();
        assert_ne!(flags(fd) & libc::FD_CLOEXEC, 0);
    }

    /// The walk alone, as on macOS and on a Linux kernel before 5.11.
    #[test]
    fn the_walk_marks_it_too_where_close_range_is_missing() {
        let file = File::open(MANIFEST).unwrap();
        let fd = inheritable(&file);
        let list = LISTS
            .into_iter()
            .find(|l| std::path::Path::new(l).is_dir())
            .unwrap();
        walk(list).unwrap();
        assert_ne!(flags(fd) & libc::FD_CLOEXEC, 0);
    }

    /// Standard input, output and error are the agent's: their flags stay.
    #[test]
    fn standard_streams_are_left_alone() {
        let before: Vec<i32> = (0..FIRST).map(flags).collect();
        close_on_exec().unwrap();
        let after: Vec<i32> = (0..FIRST).map(flags).collect();
        assert_eq!(before, after);
    }

    #[test]
    fn a_missing_listing_is_an_error() {
        assert!(walk("/nonexistent/fd-list").is_err());
    }
}

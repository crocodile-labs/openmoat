use std::net::{TcpListener, UdpSocket};
use std::os::unix::net::{UnixDatagram, UnixStream};

use super::*;

/// The real filter, on a thread of its own: the test's other threads keep
/// their sockets.
#[test]
fn the_filter_refuses_unix_and_udp_sockets_and_allows_tcp_and_socketpair() {
    let filter = seccomp_filter().expect("the filter compiles");
    let errno = |result: std::io::Result<()>| result.err().and_then(|e| e.raw_os_error());
    let (unix, udp, tcp, pair) = std::thread::spawn(move || {
        seccompiler::apply_filter(&filter).expect("the filter applies");
        (
            errno(UnixDatagram::unbound().map(drop)),
            errno(UdpSocket::bind("127.0.0.1:0").map(drop)),
            errno(TcpListener::bind("127.0.0.1:0").map(drop)),
            errno(UnixStream::pair().map(drop)),
        )
    })
    .join()
    .expect("the filtered thread finishes");
    assert_eq!((unix, udp), (Some(libc::EPERM), Some(libc::EPERM)));
    assert_eq!((tcp, pair), (None, None));
    assert!(
        UdpSocket::bind("127.0.0.1:0").is_ok(),
        "this thread is not filtered"
    );
}

/// A child on a terminal of its own (`pty.fork` makes it the controlling
/// terminal, which TIOCSTI needs) reads the window size, then pushes one
/// byte into the terminal's input. Exits with TIOCSTI's errno, 0 when it
/// went through, 255 when TIOCGWINSZ failed.
const TERMINAL_PROBE: &str = r##"
import fcntl, os, pty, termios
pid, _ = pty.fork()
if pid == 0:
    try:
        fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8))
    except OSError:
        os._exit(255)
    try:
        fcntl.ioctl(0, termios.TIOCSTI, b"#")
        os._exit(0)
    except OSError as e:
        os._exit(e.errno)
_, status = os.waitpid(pid, 0)
os._exit(os.waitstatus_to_exitcode(status))
"##;

fn terminal_probe() -> Option<i32> {
    Command::new("python3")
        .args(["-c", TERMINAL_PROBE])
        .status()
        .expect("python3 runs")
        .code()
}

/// The real filter, on a thread of its own, on a terminal the test opens.
#[test]
fn the_filter_refuses_terminal_input_and_allows_other_terminal_calls() {
    let filter = seccomp_filter().expect("the filter compiles");
    let filtered = std::thread::spawn(move || {
        seccompiler::apply_filter(&filter).expect("the filter applies");
        terminal_probe()
    })
    .join()
    .expect("the filtered thread finishes");
    assert_eq!(filtered, Some(libc::EPERM));
    // Unfiltered, TIOCSTI goes through, or fails with EIO where the kernel
    // refuses it itself (`dev.tty.legacy_tiocsti=0`): never the filter's EPERM.
    assert!(matches!(terminal_probe(), Some(0 | libc::EIO)));
}

/// Asks for the session keyring's id, makes new user, network and no
/// namespaces, calls `clone3()` without arguments and `setns()` on no file
/// (`EBADF` when it is not refused), then starts a thread and
/// forks a child that exits 7. Prints each call's errno (0 when it worked);
/// the syscall numbers come in as arguments, as they differ by architecture.
const NAMESPACE_PROBE: &str = r#"
import ctypes, os, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
keyctl, unshare, clone3, setns = (int(a) for a in sys.argv[1:5])
def call(name, nr, *args):
    ctypes.set_errno(0)
    r = libc.syscall(nr, *[ctypes.c_long(a) for a in args])
    print("%s=%d" % (name, 0 if r != -1 else ctypes.get_errno()))
call("keyctl", keyctl, 0, -3, 0)
call("newuser", unshare, 0x10000000)
call("newnet", unshare, 0x40000000)
call("none", unshare, 0)
call("clone3", clone3, 0, 0)
call("setns", setns, -1, 0)
t = threading.Thread(target=lambda: None)
t.start()
t.join()
print("thread=ok")
pid = os.fork()
if pid == 0:
    os._exit(7)
print("fork=%d" % os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
"#;

/// The real filters, on a thread of its own: the kernel keyrings, new
/// namespaces and joining one are refused with `EPERM`, `clone3()` answers
/// `ENOSYS`, and the
/// C library's threads and `fork()`, which fall back to `clone()`, still work,
/// as does starting the probe itself.
#[test]
fn the_filters_refuse_keyrings_and_new_namespaces_and_threads_still_start() {
    let filters = seccomp_filters().expect("the filters compile");
    let numbers = [
        libc::SYS_keyctl,
        libc::SYS_unshare,
        libc::SYS_clone3,
        libc::SYS_setns,
    ]
    .map(|nr| nr.to_string());
    let out = std::thread::spawn(move || {
        for filter in &filters {
            seccompiler::apply_filter(filter).expect("the filter applies");
        }
        Command::new("python3")
            .args(["-c", NAMESPACE_PROBE])
            .args(numbers)
            .output()
            .expect("python3 starts under the filters")
    })
    .join()
    .expect("the filtered thread finishes");
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let expected = [
        format!("keyctl={}", libc::EPERM),
        format!("newuser={}", libc::EPERM),
        format!("newnet={}", libc::EPERM),
        "none=0".to_owned(),
        format!("clone3={}", libc::ENOSYS),
        format!("setns={}", libc::EPERM),
        "thread=ok".to_owned(),
        "fork=7".to_owned(),
    ];
    for line in expected {
        assert!(shown.lines().any(|l| l == line), "{line}: {shown}");
    }
}

/// Only terminal devices the streams are on: never `/dev/tty`, a pipe or
/// `/dev/null`.
#[test]
fn the_terminals_are_the_streams_own_ttys() {
    for terminal in terminals() {
        let pts = terminal.starts_with("/dev/pts/") && terminal != "/dev/pts/ptmx";
        assert!(
            pts || (terminal.starts_with("/dev/tty") && terminal != "/dev/tty"),
            "{terminal}"
        );
    }
}

/// Sends on an unconnected TCP socket to a local listener, first with
/// `MSG_FASTOPEN` (which would connect it), then a plain `connect()` and
/// `send`. Prints the errno of each, 0 when it went through.
const FAST_OPEN_PROBE: &str = r#"
import socket, sys
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(1)
addr = listener.getsockname()
def errno(f):
    try:
        f()
        return 0
    except OSError as e:
        return e.errno
s = socket.socket()
fast = errno(lambda: s.sendto(b"x", socket.MSG_FASTOPEN, addr))
t = socket.socket()
plain = errno(lambda: (t.connect(addr), t.send(b"x")))
print(fast, plain)
"#;

fn fast_open_probe() -> String {
    let out = Command::new("python3")
        .args(["-c", FAST_OPEN_PROBE])
        .output()
        .expect("python3 runs");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// TCP Fast Open connects inside `sendto()`, past Landlock's `connect()`
/// check: the filter refuses a send that asks for it, and no other.
#[test]
fn the_filter_refuses_tcp_fast_open_and_allows_other_sends() {
    let filter = seccomp_filter().expect("the filter compiles");
    let filtered = std::thread::spawn(move || {
        seccompiler::apply_filter(&filter).expect("the filter applies");
        fast_open_probe()
    })
    .join()
    .expect("the filtered thread finishes");
    assert_eq!(filtered, format!("{} 0", libc::EPERM));
    // Unfiltered, the same send goes through, or fails as the kernel's
    // `net.ipv4.tcp_fastopen` setting says: never the filter's EPERM.
    let unfiltered = fast_open_probe();
    assert!(
        unfiltered.ends_with(" 0") && !unfiltered.starts_with(&format!("{} ", libc::EPERM)),
        "{unfiltered}"
    );
}

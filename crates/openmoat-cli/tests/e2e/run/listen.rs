//! `openmoat run --listen PORT` (ADR-108 §7): inside, a bind to that one port
//! on loopback works; a bind to another port, and a connection to the port
//! (only the proxy is reachable), are refused. The agent's network namespace
//! has loopback alone, so there it may bind any address, reachable from
//! nowhere else. Linux without a namespace, and macOS (whose Seatbelt filter
//! lets a bind to every address on the port through), refuse `--listen`
//! before anything starts.

use std::net::{Ipv4Addr, TcpListener};

use super::confined::ran;
use super::{check_netns, installed_with_secret, run_sh_flags};
use crate::common::{USAGE, stderr, stdout, text};

/// Prints `name=0` for each call that went through, `name=<errno>` for each
/// refused one; `{port}` and `{other}` are replaced.
const PROBE: &str = r#"python3 -c '
import socket
def errno(f):
    try:
        f()
        return "0"
    except OSError as e:
        return str(e.errno)
def bind(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    s.close()
def connect(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(("127.0.0.1", port))
    finally:
        s.close()
print("loopback=" + errno(lambda: bind("127.0.0.1", {port})))
print("other=" + errno(lambda: bind("127.0.0.1", {other})))
print("every=" + errno(lambda: bind("0.0.0.0", {port})))
held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
held.bind(("127.0.0.1", {port}))
held.listen(1)
print("connect=" + errno(lambda: connect({port})))
'"#;

/// Two ports free on this machine's loopback now.
fn free_ports() -> (u16, u16) {
    let a = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let b = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    )
}

#[test]
fn listen_allows_one_loopback_port_and_no_other_bind() {
    let (sb, project) = installed_with_secret();
    let (port, other) = free_ports();
    let script = PROBE
        .replace("{port}", &port.to_string())
        .replace("{other}", &other.to_string());
    let out = run_sh_flags(
        &sb,
        &project,
        &["--listen", &port.to_string()],
        &script,
        &[],
    );
    let shown = text(&out);
    if cfg!(target_os = "macos") {
        // Seatbelt lets a bind to every address on the port through too, so
        // the port could be reachable from the network: refused.
        assert_eq!(out.status.code(), Some(USAGE), "{shown}");
        assert!(stderr(&out).contains("refused on macOS"), "{shown}");
        assert!(!stdout(&out).contains("loopback="), "{shown}");
        return;
    }
    if !ran(&out) {
        return;
    }
    if cfg!(target_os = "linux") {
        let port_only = stderr(&out).contains("needs a network of the agent's own");
        check_netns(port_only, &shown);
        if port_only {
            // Landlock alone would open the port on every address: refused.
            assert_eq!(out.status.code(), Some(USAGE), "{shown}");
            assert!(!stdout(&out).contains("loopback="), "{shown}");
            return;
        }
    }
    let said = stdout(&out);
    assert!(said.contains("loopback=0\n"), "{shown}");
    assert!(
        said.contains("other=") && !said.contains("other=0\n"),
        "{shown}"
    );
    assert!(
        said.contains("connect=") && !said.contains("connect=0\n"),
        "{shown}"
    );
}

/// Without `--listen`, no bind at all.
#[test]
fn without_listen_no_port_can_be_bound() {
    let (sb, project) = installed_with_secret();
    let (port, other) = free_ports();
    let script = PROBE
        .replace("{port}", &port.to_string())
        .replace("{other}", &other.to_string());
    let out = run_sh_flags(&sb, &project, &[], &script, &[]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    let said = stdout(&out);
    assert!(
        said.contains("loopback=") && !said.contains("loopback=0\n"),
        "{shown}"
    );
}

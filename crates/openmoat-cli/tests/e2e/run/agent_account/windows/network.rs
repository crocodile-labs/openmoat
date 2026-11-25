//! The agent account's network filters (ADR-129 step 2), seen from a run:
//! a direct connection to an address of this machine that is not loopback
//! is refused, one through the run's proxy is answered, and a listen is
//! refused. No packet leaves the machine: the direct one goes to this
//! machine's own address, where the test listens, and the proxied request
//! names loopback, which the proxy itself refuses with 403.

use std::io::ErrorKind;
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;

use super::run_cmd;
use crate::common::{OK, Sandbox, stdout, text};

/// This machine's address on its default route: a UDP socket's `connect`
/// picks it and sends nothing.
fn own_address() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    let ip = socket.local_addr().unwrap().ip();
    assert!(
        !ip.is_loopback() && !ip.is_unspecified(),
        "this machine has no address but loopback: {ip}"
    );
    ip
}

/// Every network case of a run as the account with its filters.
pub(super) fn the_filters_hold_the_account(sb: &Sandbox, project: &Path, account: &str) {
    // A listener of the test's own (the runner's user, which no filter
    // names) on this machine's address.
    let ip = own_address();
    let listener = TcpListener::bind((ip, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = listener.local_addr().unwrap();

    // Direct, past the proxy variables: refused before a packet is sent.
    let script = format!(
        "curl.exe -sS -m 10 --noproxy * -o NUL http://{target}/ && echo direct=open || echo \
         direct=refused"
    );
    let out = run_cmd(sb, project, account, &script);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stdout(&out).contains("direct=refused"), "{}", text(&out));
    // Nothing reached the listener; the address itself is reachable, as a
    // connection of the test's own shows.
    assert!(
        listener
            .accept()
            .is_err_and(|e| e.kind() == ErrorKind::WouldBlock),
        "the account's connection reached {target}: {}",
        text(&out)
    );
    drop(TcpStream::connect(target).unwrap());
    let mut accepted = false;
    for _ in 0..50 {
        if listener.accept().is_ok() {
            accepted = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(accepted, "{target} is not reachable even for the test");

    // Through the proxy variables: the proxy answers, and refuses loopback.
    let out = run_cmd(
        sb,
        project,
        account,
        "curl.exe -sS -m 30 -o NUL -w proxy=%{http_code} http://127.0.0.1:9/",
    );
    assert!(stdout(&out).contains("proxy=403"), "{}", text(&out));

    // A listen, even on loopback: refused. PowerShell joins the arguments
    // after `-Command` into its script, so no quote has to pass `cmd`.
    let out = run_cmd(
        sb,
        project,
        account,
        "powershell.exe -NoProfile -NonInteractive -Command $l = \
         [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); try { $l.Start(); \
         'listen=open' } catch { 'listen=refused' }",
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stdout(&out).contains("listen=refused"), "{}", text(&out));
}

/// Whether the filtering engine still holds any of `keys` (GUIDs), from
/// `netsh wfp show filters`, which writes every filter to a file.
pub(super) fn engine_holds_any(dir: &Path, keys: &[String]) -> bool {
    let file = dir.join("filters.xml");
    let out = std::process::Command::new("netsh")
        .args(["wfp", "show", "filters"])
        .arg(format!("file={}", file.display()))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let shown = std::fs::read(&file).unwrap();
    // netsh writes UTF-8 or UTF-16; compare in lower case either way.
    let shown = if shown.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = shown[2..]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&shown).into_owned()
    }
    .to_lowercase();
    keys.iter().any(|key| shown.contains(&key.to_lowercase()))
}

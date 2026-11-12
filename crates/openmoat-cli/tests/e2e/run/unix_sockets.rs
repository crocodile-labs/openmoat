//! Linux: pathname Unix sockets outside the sandbox stay out of reach, and the
//! kernel's Landlock ABI is shown and on record (ADR-082). Below ABI 9 the
//! seccomp filter alone refuses the datagram socket pair that could send to
//! one; at ABI 9 Landlock refuses the send as well.

use std::io::ErrorKind;
use std::os::unix::net::UnixDatagram;

use super::confined::ran;
use super::{LIGHTWEIGHT, installed_with_secret, run_sh_flags};
use crate::common::{Sandbox, stderr, stdout, text};

/// Makes a datagram, a stream and a sequenced-packet socket pair, then sends
/// from a datagram pair to the socket at `{path}`. Prints each errno, 0 when
/// the call went through.
const PROBE: &str = r#"python3 -c '
import socket
def errno(f):
    try:
        f()
        return "0"
    except OSError as e:
        return str(e.errno)
pair = lambda kind: socket.socketpair(socket.AF_UNIX, kind)
print("dgram=" + errno(lambda: pair(socket.SOCK_DGRAM)))
print("stream=" + errno(lambda: pair(socket.SOCK_STREAM)))
print("seqpacket=" + errno(lambda: pair(socket.SOCK_SEQPACKET)))
print("sent=" + errno(lambda: pair(socket.SOCK_DGRAM)[0].sendto(b"x", "{path}")))
'"#;

/// The rules of the run's `run-landlock-abi` rows.
fn landlock_rows(sb: &Sandbox) -> Vec<String> {
    let store = openmoat_audit::Store::open_read_only(&sb.home.join(".moat/audit.db")).unwrap();
    store
        .since(0, Some("moat-run"))
        .unwrap()
        .into_iter()
        .filter(|event| event.tool == "landlock")
        .flat_map(|event| event.rules)
        .collect()
}

#[test]
fn a_datagram_pair_is_refused_and_nothing_reaches_a_socket_outside() {
    let (sb, project) = installed_with_secret();
    let path = sb.home.with_file_name("outside.sock");
    let shown_path = path.to_string_lossy().into_owned();
    // A socket's path must fit in 108 bytes.
    if shown_path.len() > 100 {
        eprintln!("skipped: the test directory's path is too long for a socket");
        return;
    }
    let _ = std::fs::remove_file(&path);
    let outside = UnixDatagram::bind(&path).unwrap();
    outside.set_nonblocking(true).unwrap();
    let script = PROBE.replace("{path}", &shown_path);
    let out = run_sh_flags(&sb, &project, &[LIGHTWEIGHT, "--verbose"], &script, &[]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    let eperm = libc::EPERM;
    for expected in [
        format!("dgram={eperm}\n"),
        "stream=0\n".to_owned(),
        "seqpacket=0\n".to_owned(),
        format!("sent={eperm}\n"),
    ] {
        assert!(stdout(&out).contains(&expected), "{expected}: {shown}");
    }
    assert_eq!(
        outside.recv(&mut [0; 1]).map_err(|e| e.kind()),
        Err(ErrorKind::WouldBlock),
        "nothing reached the socket outside"
    );
    // `--verbose` shows the ladder, and the run is on record with its ABI.
    assert!(stderr(&out).contains("Landlock ABI "), "{shown}");
    assert!(stderr(&out).contains("ABI 9 (Linux 7.1)"), "{shown}");
    assert_eq!(landlock_rows(&sb), ["run-landlock-abi"]);
}

#[test]
fn doctor_and_sandbox_show_name_the_kernels_landlock_abi() {
    let (sb, _project) = installed_with_secret();
    let json = sb.moat(&["sandbox", "show", "--format", "json"]);
    let doc: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let abi = &doc["lightweight"]["landlock"]["abi"];
    assert_eq!(abi["floor"], 4, "{abi}");
    let doctor = sb.moat(&["doctor", "--verbose"]);
    // Below ABI 4, or without Landlock, `openmoat run` refuses to start
    // (`confined::ran`). CI kernels have it, so there the test must run.
    if !abi["kernel"]["abi"].as_u64().is_some_and(|n| n >= 4) {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI's kernel must have Landlock ABI 4: {abi}"
        );
        assert!(
            text(&doctor).contains("`openmoat run` refuses to start"),
            "{}",
            text(&doctor)
        );
        eprintln!("skipped: this kernel has no Landlock ABI 4");
        return;
    }
    assert!(text(&doctor).contains("Landlock ABI "), "{}", text(&doctor));
    let show = sb.moat(&["sandbox", "show"]);
    assert!(
        stdout(&show).contains("ABI 4 (Linux 6.7)"),
        "{}",
        text(&show)
    );
}

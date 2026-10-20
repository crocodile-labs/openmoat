//! `moat run` on Linux reaches only OpenMoat's proxy on loopback. Landlock
//! allows the proxy's port on every host, so where bubblewrap runs the agent
//! gets a network namespace with loopback alone; elsewhere `moat run` says
//! the network is restricted by port only.

use std::process::Output;

use super::confined::{ran, retried};
use super::{installed_with_secret, run_sh};
use crate::common::{stderr, stdout, text};

/// Linux's `ENETUNREACH`: no route, as in a namespace with loopback alone.
const ENETUNREACH: &str = "101";

/// False, saying so, where `moat run` started without a network namespace
/// (bubblewrap missing or unable to make one). CI's Linux jobs install it, so
/// there the namespace must be used.
fn namespaced(out: &Output) -> bool {
    let port_only = stderr(out).contains("restricted by port only");
    assert!(
        !(port_only && std::env::var_os("CI").is_some()),
        "CI must run `moat run` in a network namespace: {}",
        text(out)
    );
    if port_only {
        eprintln!("skipped: bubblewrap cannot make a network namespace here");
    }
    !port_only
}

/// A connection to the proxy's port number on another address (TEST-NET-1,
/// RFC 5737) has no route, and the proxy itself still answers on loopback.
#[test]
fn the_proxy_port_on_another_host_is_unreachable() {
    let (sb, project) = installed_with_secret();
    let script = r#"port="${HTTPS_PROXY##*:}"
         python3 -c '
import socket, sys
try:
    socket.create_connection(("192.0.2.1", int(sys.argv[1])), timeout=10).close()
    print("other=open")
except OSError as e:
    print("other=" + str(e.errno))
' "$port"
         curl -sS -m 30 -o /dev/null -w 'proxy=%{http_code}\n' http://127.0.0.1:9/"#;
    let out = retried(|| run_sh(&sb, &project, script));
    if !ran(&out) || !namespaced(&out) {
        return;
    }
    let shown = text(&out);
    assert!(
        stdout(&out).contains(&format!("other={ENETUNREACH}\n")),
        "{shown}"
    );
    // Through the relay the proxy decides the request: loopback is refused.
    assert!(stdout(&out).contains("proxy=403"), "{shown}");
    assert!(
        stderr(&out).contains("network only through OpenMoat's proxy on 127.0.0.1:"),
        "{shown}"
    );
}

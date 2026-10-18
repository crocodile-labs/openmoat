//! Private, CGNAT and unique-local addresses, and addresses a deny rule
//! names, behind allowed names. An opt-in
//! cannot be shown end to end without connecting to a private address, so
//! `decide::tests` covers it on the decision function.

use super::*;

#[test]
fn an_allowed_name_on_the_local_network_is_refused() {
    let h = start(None, Limits::default());
    for (host, range) in [
        ("lan.test", "10.0.0.0/8"),
        // one private address refuses the name, even beside a public one
        ("mixed-lan.test", "192.168.0.0/16"),
        // a wildcard allow does not name an address
        ("x.wild.test", "fc00::/7"),
    ] {
        let reply = h.exchange(&format!("GET http://{host}/ HTTP/1.1\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 403"), "{host}: {reply}");
        assert!(reply.contains(range), "{host}: {reply}");
        let reply = h.exchange(&format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 403"), "{host}: {reply}");
    }
    assert!(h.nothing_forwarded());
    let rows = h.rows();
    assert_eq!(rows.len(), 6);
    assert!(
        rows.iter()
            .all(|r| r.verdict == Verdict::Deny && r.rules == ["proxy-address"])
    );
}

#[test]
fn an_allowed_name_resolving_to_a_denied_address_is_refused() {
    let h = start(None, Limits::default());
    let port = h.port();
    for (host, ip) in [
        ("denied.test", "203.0.113.7"),
        // one denied address refuses the name, even beside one that would connect
        ("mixed-denied.test", "203.0.113.7"),
        ("denied-v6.test", "2001:db8::5"),
    ] {
        let reply = h.exchange(&format!("GET http://{host}:{port}/ HTTP/1.1\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 403"), "{host}: {reply}");
        assert!(
            reply.contains(ip) && reply.contains("no-doc-net"),
            "{host}: {reply}"
        );
        let reply = h.exchange(&format!("CONNECT {host}:{port} HTTP/1.1\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 403"), "{host}: {reply}");
    }
    assert!(h.nothing_forwarded());
    let rows = h.rows();
    assert_eq!(rows.len(), 6);
    assert!(rows.iter().all(|r| r.verdict == Verdict::Deny
        && r.rules == ["proxy-address"]
        && r.reasons[0].contains("`no-doc-net`")));
}

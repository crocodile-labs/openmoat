//! Audit delivery's `POST` (ADR-081) against local servers: HTTPS verified
//! against the CA it is given, plain HTTP to loopback, and the addresses it
//! never reaches.

use openmoat_proxy::{Endpoint, PostError, Poster, Roots};

use super::terminate::{https_upstream, upstream_tls};
use super::*;

fn poster(roots: &Roots, names: &[(&'static str, IpAddr)]) -> Poster {
    let map = names.iter().map(|(n, ip)| (*n, vec![*ip])).collect();
    Poster::new(roots, Box::new(MapResolver(map))).unwrap()
}

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[test]
fn an_https_post_is_verified_against_the_given_ca_and_sends_the_body() {
    let (ca, config) = upstream_tls();
    let (addr, heads) = https_upstream(config);
    let client = poster(&Roots::Pem(ca), &[("owner.test", LOOPBACK)]);
    let endpoint = Endpoint::parse(&format!("https://owner.test:{}/v1/logs", addr.port())).unwrap();
    let answer = client
        .post(
            &endpoint,
            &[("Content-Type", "application/json")],
            b"{}",
            WAIT,
        )
        .unwrap();
    assert!(answer.accepted(), "{answer:?}");
    let head = String::from_utf8(heads.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(head.starts_with("POST /v1/logs HTTP/1.1\r\n"), "{head}");
    assert!(head.contains("Content-Length: 2\r\n"), "{head}");
    assert!(
        head.contains("Content-Type: application/json\r\n"),
        "{head}"
    );
}

#[test]
fn a_server_another_ca_signed_is_refused() {
    let (_, config) = upstream_tls();
    let (other_ca, _) = upstream_tls();
    let (addr, _heads) = https_upstream(config);
    let client = poster(&Roots::Pem(other_ca), &[("owner.test", LOOPBACK)]);
    let endpoint = Endpoint::parse(&format!("https://owner.test:{}/", addr.port())).unwrap();
    let error = client.post(&endpoint, &[], b"{}", WAIT).unwrap_err();
    assert!(
        matches!(error, PostError::Io(_) | PostError::Tls(_)),
        "{error}"
    );
}

#[test]
fn plain_http_reaches_loopback_and_reads_the_status() {
    let (addr, firsts) = upstream();
    let (ca, _) = upstream_tls();
    let client = poster(&Roots::Pem(ca), &[]);
    let endpoint = Endpoint::parse(&format!("http://127.0.0.1:{}/hook", addr.port())).unwrap();
    let answer = client.post(&endpoint, &[], b"hello", WAIT).unwrap();
    assert_eq!(answer.status, 200);
    let got = String::from_utf8(firsts.recv_timeout(WAIT).unwrap()).unwrap();
    assert!(got.starts_with("POST /hook HTTP/1.1\r\n"), "{got}");
}

#[test]
fn a_name_pointed_at_metadata_or_off_machine_over_http_is_refused_unsent() {
    let (ca, _) = upstream_tls();
    let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    let lan = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    let client = poster(
        &Roots::Pem(ca),
        &[("rebind.test", metadata), ("localhost", lan)],
    );
    let https = Endpoint::parse("https://rebind.test/").unwrap();
    assert!(matches!(
        client.post(&https, &[], b"{}", WAIT),
        Err(PostError::Address { .. })
    ));
    // `localhost` that resolves off the machine is not sent plain text.
    let plain = Endpoint::parse("http://localhost:4318/v1/logs").unwrap();
    assert!(matches!(
        client.post(&plain, &[], b"{}", WAIT),
        Err(PostError::PlainOffMachine { .. })
    ));
}

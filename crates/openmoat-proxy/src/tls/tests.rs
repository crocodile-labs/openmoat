use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier as _;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection};

use super::date::Day;
use super::{Roots, Tls, TlsError, new_ca};

const HOST: &str = "owner.test";

fn hosts(names: &[&str]) -> Vec<String> {
    names.iter().map(|h| (*h).to_owned()).collect()
}

/// A root store holding `pem` alone.
fn roots(pem: &str) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pem.as_bytes()).unwrap())
        .unwrap();
    roots
}

/// Any CA, for upstream roots the tests never use.
fn upstream_roots() -> Roots {
    Roots::Pem(new_ca(&hosts(&["upstream.test"])).unwrap().cert_pem)
}

fn tls_for(names: &[&str]) -> (String, Tls) {
    let ca = new_ca(&hosts(names)).unwrap();
    let tls = Tls::new(&ca.cert_pem, &ca.key_pem, &upstream_roots(), &hosts(names)).unwrap();
    (ca.cert_pem, tls)
}

fn client(ca_pem: &str, alpn: &[&[u8]]) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(ca_pem))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// Run a handshake in memory; the error, if any, as each side saw it.
fn handshake(mut c: ClientConnection, mut s: ServerConnection) -> Result<Option<Vec<u8>>, String> {
    for _ in 0..20 {
        let mut wire = Vec::new();
        c.write_tls(&mut wire).unwrap();
        s.read_tls(&mut wire.as_slice()).unwrap();
        s.process_new_packets()
            .map_err(|e| format!("server: {e}"))?;
        let mut back = Vec::new();
        s.write_tls(&mut back).unwrap();
        c.read_tls(&mut back.as_slice()).unwrap();
        c.process_new_packets()
            .map_err(|e| format!("client: {e}"))?;
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok(c.alpn_protocol().map(<[u8]>::to_vec));
        }
    }
    Err("no end".to_owned())
}

#[test]
fn a_client_that_trusts_the_ca_completes_the_handshake_on_http_1_1() {
    let (ca, tls) = tls_for(&[HOST]);
    for alpn in [
        &[][..],
        &[b"http/1.1".as_slice()][..],
        &[b"h2".as_slice(), b"http/1.1"][..],
    ] {
        let c = ClientConnection::new(
            Arc::new(client(&ca, alpn)),
            ServerName::try_from(HOST).unwrap(),
        )
        .unwrap();
        let got = handshake(c, tls.accept(HOST).unwrap()).unwrap();
        let expected = (!alpn.is_empty()).then(|| b"http/1.1".to_vec());
        assert_eq!(got, expected, "{alpn:?}");
    }
}

#[test]
fn an_http_2_only_client_is_refused_in_the_handshake() {
    let (ca, tls) = tls_for(&[HOST]);
    let c = ClientConnection::new(
        Arc::new(client(&ca, &[b"h2"])),
        ServerName::try_from(HOST).unwrap(),
    )
    .unwrap();
    let err = handshake(c, tls.accept(HOST).unwrap()).unwrap_err();
    assert!(err.contains("known protocol"), "{err}");
}

#[test]
fn a_client_without_the_ca_refuses_the_leaf() {
    let (_, tls) = tls_for(&[HOST]);
    let (other, _) = tls_for(&[HOST]);
    let c = ClientConnection::new(
        Arc::new(client(&other, &[])),
        ServerName::try_from(HOST).unwrap(),
    )
    .unwrap();
    let err = handshake(c, tls.accept(HOST).unwrap()).unwrap_err();
    assert!(
        err.starts_with("client:") && err.contains("certificate"),
        "{err}"
    );
}

#[test]
fn the_ca_cannot_vouch_for_a_host_outside_its_constraints() {
    // The key would sign a leaf for anything: clients refuse it by the CA's
    // name constraints, and the proxy refuses to start for such a host.
    let ca = new_ca(&hosts(&[HOST])).unwrap();
    for outside in [
        "evil.test",
        "api.github.com",
        "owner.test.evil.test",
        "xowner.test",
    ] {
        let err = Tls::new(
            &ca.cert_pem,
            &ca.key_pem,
            &upstream_roots(),
            &hosts(&[outside]),
        )
        .unwrap_err();
        assert!(
            matches!(err, TlsError::Uncovered { ref host, .. } if host == outside),
            "{err}"
        );
        // A client trusting the CA rejects the leaf a terminating proxy would show.
        let tls = Tls::new(&ca.cert_pem, &ca.key_pem, &upstream_roots(), &[]).unwrap();
        let c = ClientConnection::new(
            Arc::new(client(&ca.cert_pem, &[])),
            ServerName::try_from(outside.to_owned()).unwrap(),
        )
        .unwrap();
        let refused = handshake(c, tls.accept(outside).unwrap()).unwrap_err();
        assert!(refused.contains("client:"), "{outside}: {refused}");
    }
    // A name under a covered host is in the subtree (RFC 5280 §4.2.1.10).
    assert!(
        Tls::new(
            &ca.cert_pem,
            &ca.key_pem,
            &upstream_roots(),
            &hosts(&["api.owner.test"])
        )
        .is_ok()
    );
}

#[test]
fn a_key_that_is_not_the_cas_is_refused() {
    let one = new_ca(&hosts(&[HOST])).unwrap();
    let two = new_ca(&hosts(&[HOST])).unwrap();
    let err = Tls::new(
        &one.cert_pem,
        &two.key_pem,
        &upstream_roots(),
        &hosts(&[HOST]),
    )
    .unwrap_err();
    assert!(matches!(err, TlsError::Uncovered { .. }), "{err}");
    let err = Tls::new(&one.cert_pem, "not a key", &upstream_roots(), &[]).unwrap_err();
    assert!(matches!(err, TlsError::Key), "{err}");
    let err = Tls::new("not a cert", &one.key_pem, &upstream_roots(), &[]).unwrap_err();
    assert!(matches!(err, TlsError::Cert), "{err}");
    let err = Tls::new(&one.cert_pem, &one.key_pem, &Roots::Pem(String::new()), &[]).unwrap_err();
    assert!(matches!(err, TlsError::NoRoots), "{err}");
    assert!(matches!(new_ca(&[]), Err(TlsError::NoHosts)));
    assert!(
        !format!("{one:?}").contains("PRIVATE"),
        "the key is not in Debug"
    );
}

#[test]
fn the_ca_is_valid_a_year_and_its_leaves_three_days() {
    let ca = new_ca(&hosts(&[HOST])).unwrap();
    let tls = Tls::new(&ca.cert_pem, &ca.key_pem, &upstream_roots(), &[]).unwrap();
    let (leaf, _) = tls.signer.leaf(HOST, Day::today().unwrap()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots(&ca.cert_pem)),
        provider,
    )
    .build()
    .unwrap();
    let at = |days: i64| {
        let now = UnixTime::now().as_secs();
        let secs = now.checked_add_signed(days * 86_400).unwrap();
        verifier.verify_server_cert(
            &CertificateDer::from(leaf.clone()),
            &[],
            &ServerName::try_from(HOST).unwrap(),
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs)),
        )
    };
    assert!(at(0).is_ok());
    assert!(at(1).is_ok());
    assert!(at(3).is_err(), "the leaf has expired");
    assert!(at(-2).is_err(), "the leaf is not valid yet");
}

#[test]
fn days_are_civil_dates() {
    for (days, ymd) in [
        (0, (1970, 1, 1)),
        (11_016, (2000, 2, 29)),
        (11_017, (2000, 3, 1)),
        (19_723, (2024, 1, 1)),
        (19_782, (2024, 2, 29)),
        (20_753, (2026, 10, 27)),
    ] {
        assert_eq!(super::date::Day(days).civil(), ymd, "{days}");
    }
    assert!(Day::of(std::time::UNIX_EPOCH - std::time::Duration::from_secs(1)).is_none());
    assert!(Day(-1).ymd().is_err());
}

use super::*;

fn u16b(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap().to_be_bytes()
}

/// A `ClientHello` body with the given extensions, as (type, data) pairs.
fn hello_body(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut b = vec![3, 3];
    b.extend([7; 32]); // random
    b.extend([0]); // session id
    b.extend([0, 2, 0x13, 0x01]); // one cipher suite
    b.extend([1, 0]); // null compression
    let mut ext = Vec::new();
    for (kind, data) in exts {
        ext.extend(kind.to_be_bytes());
        ext.extend(u16b(data.len()));
        ext.extend(data);
    }
    b.extend(u16b(ext.len()));
    b.extend(ext);
    b
}

fn sni_ext(names: &[(u8, &[u8])]) -> (u16, Vec<u8>) {
    let mut list = Vec::new();
    for (kind, name) in names {
        list.push(*kind);
        list.extend(u16b(name.len()));
        list.extend(*name);
    }
    let mut data = u16b(list.len()).to_vec();
    data.extend(list);
    (EXT_SERVER_NAME, data)
}

fn handshake(body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut hs = vec![HANDSHAKE_CLIENT_HELLO, len[1], len[2], len[3]];
    hs.extend(body);
    hs
}

/// `hs` split into TLS records of at most `chunk` bytes.
fn records(hs: &[u8], chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for part in hs.chunks(chunk) {
        out.extend([CONTENT_HANDSHAKE, 3, 1]);
        out.extend(u16b(part.len()));
        out.extend(part);
    }
    out
}

fn hello_for(name: &str) -> Vec<u8> {
    let alpn = (16, vec![0, 3, 2, b'h', b'2']);
    records(
        &handshake(&hello_body(&[alpn, sni_ext(&[(0, name.as_bytes())])])),
        16384,
    )
}

#[test]
fn reads_the_server_name() {
    assert_eq!(
        server_name(&hello_for("Api.Example.com.")),
        Ok(Hello::ServerName(Some("api.example.com".to_owned())))
    );
}

#[test]
fn a_hello_without_sni_has_no_name() {
    let no_ext = records(&handshake(&hello_body(&[(16, vec![0, 0])])), 16384);
    assert_eq!(server_name(&no_ext), Ok(Hello::ServerName(None)));
    let mut bare = hello_body(&[]);
    bare.truncate(bare.len() - 2); // no extensions block at all
    let bare = records(&handshake(&bare), 16384);
    assert_eq!(server_name(&bare), Ok(Hello::ServerName(None)));
}

#[test]
fn reassembles_a_hello_split_over_records() {
    let split = records(
        &handshake(&hello_body(&[sni_ext(&[(0, b"example.com")])])),
        7,
    );
    assert_eq!(
        server_name(&split),
        Ok(Hello::ServerName(Some("example.com".to_owned())))
    );
}

#[test]
fn every_prefix_is_incomplete_or_an_answer() {
    let full = hello_for("example.com");
    for n in 0..full.len() {
        assert_eq!(server_name(&full[..n]), Ok(Hello::Incomplete), "prefix {n}");
    }
}

#[test]
fn non_tls_and_malformed_hellos_are_refused() {
    assert_eq!(
        server_name(b"SSH-2.0-OpenSSH_9.6\r\n"),
        Err(HelloError::NotTls)
    );
    assert_eq!(
        server_name(b"GET / HTTP/1.1\r\n\r\n"),
        Err(HelloError::NotTls)
    );
    // a handshake record that is not a ClientHello (ServerHello = 2)
    let mut server_hello = handshake(&hello_body(&[]));
    server_hello[0] = 2;
    assert_eq!(
        server_name(&records(&server_hello, 16384)),
        Err(HelloError::Malformed)
    );
    // two host names, two SNI extensions, an empty or non-ASCII name
    for exts in [
        vec![sni_ext(&[(0, b"a.com"), (0, b"b.com")])],
        vec![sni_ext(&[(0, b"a.com")]), sni_ext(&[(0, b"b.com")])],
        vec![sni_ext(&[(0, b"")])],
        vec![sni_ext(&[(0, "é.com".as_bytes())])],
    ] {
        let raw = records(&handshake(&hello_body(&exts)), 16384);
        assert_eq!(server_name(&raw), Err(HelloError::Malformed), "{exts:?}");
    }
    // a length that runs past the message
    let mut body = hello_body(&[sni_ext(&[(0, b"a.com")])]);
    let last = body.len() - 1;
    body.truncate(last);
    assert_eq!(
        server_name(&records(&handshake(&body), 16384)),
        Err(HelloError::Malformed)
    );
}

#[test]
fn names_that_are_not_dns_names_are_refused() {
    for name in [&b"."[..], b"..", b"a..com", b"a com", b"a.com\0"] {
        let raw = records(&handshake(&hello_body(&[sni_ext(&[(0, name)])])), 16384);
        assert_eq!(server_name(&raw), Err(HelloError::Malformed), "{name:?}");
    }
}

/// Fuzz crash (#244): a `host_name` of `.` came out as an empty name.
#[test]
fn a_root_dot_name_is_malformed_not_empty() {
    let crash = [
        0x16, 0x03, 0x01, 0x00, 0x43, 0x01, 0x00, 0x00, 0x3f, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x04, 0xff, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x40, 0x00, 0x00,
        0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x3b, 0x00,
        0x01, 0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2e, 0x00, 0x00, 0x6d,
    ];
    assert_eq!(server_name(&crash), Err(HelloError::Malformed));
}

#[test]
fn unknown_name_types_are_skipped() {
    let raw = records(
        &handshake(&hello_body(&[sni_ext(&[(9, b"x"), (0, b"a.com")])])),
        16384,
    );
    assert_eq!(
        server_name(&raw),
        Ok(Hello::ServerName(Some("a.com".to_owned())))
    );
}

/// An ECH or ESNI extension marks the hello, before or after the SNI, with or
/// without one: the cleartext name may front for another.
#[test]
fn an_encrypted_server_name_is_reported_with_the_cleartext_one() {
    let ech = (EXT_ECH, vec![0, 0, 1, 0, 1, 7]);
    let esni = (EXT_ESNI, vec![0x13, 0x01, 0, 0]);
    let sni = sni_ext(&[(0, b"front.example")]);
    for exts in [
        vec![sni.clone(), ech.clone()],
        vec![ech.clone(), sni.clone()],
        vec![sni.clone(), esni.clone()],
    ] {
        let raw = records(&handshake(&hello_body(&exts)), 16384);
        assert_eq!(
            server_name(&raw),
            Ok(Hello::Encrypted(Some("front.example".to_owned()))),
            "{exts:?}"
        );
    }
    let raw = records(&handshake(&hello_body(&[ech])), 16384);
    assert_eq!(server_name(&raw), Ok(Hello::Encrypted(None)));
    // Neighbouring extension types are not taken for it.
    let raw = records(
        &handshake(&hello_body(&[sni, (0xfe0c, vec![]), (0xffcd, vec![])])),
        16384,
    );
    assert_eq!(
        server_name(&raw),
        Ok(Hello::ServerName(Some("front.example".to_owned())))
    );
}

#[test]
fn oversized_hellos_are_refused() {
    let mut huge = vec![HANDSHAKE_CLIENT_HELLO, 0x10, 0, 0];
    huge.extend([0; 16]);
    assert_eq!(
        server_name(&records(&huge, 16384)),
        Err(HelloError::TooLarge)
    );
}

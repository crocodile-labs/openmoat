use std::collections::HashMap;

use openmoat_core::TaintSecret;

use super::*;

pub(crate) const TOKEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(crate) const TOKEN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Fixed taint per session; an unknown session is an error.
pub(crate) struct Fixed(pub(crate) HashMap<&'static str, Taint>);

impl TaintLookup for Fixed {
    fn taint(&self, session: &str) -> Result<Taint, String> {
        self.0
            .get(session)
            .cloned()
            .ok_or_else(|| format!("no session {session}"))
    }
}

fn encode(raw: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The `Proxy-Authorization` value a client sends for `user:password`.
pub(crate) fn header(user: &str, password: &str) -> String {
    format!("Basic {}", encode(format!("{user}:{password}").as_bytes()))
}

/// Sessions `run-a` (`TOKEN_A`) and `run-b` (`TOKEN_B`).
pub(crate) fn two_sessions(lookup: &Fixed) -> Sessions<'_> {
    Sessions::new(
        vec![
            Credential::new("run-a", TOKEN_A.as_bytes()).unwrap(),
            Credential::new("run-b", TOKEN_B.as_bytes()).unwrap(),
        ],
        lookup,
    )
}

#[test]
fn a_valid_credential_names_its_own_session() {
    let lookup = Fixed(HashMap::new());
    let sessions = two_sessions(&lookup);
    assert_eq!(sessions.verify(&[header("run-a", TOKEN_A)]), Ok("run-a"));
    assert_eq!(sessions.verify(&[header("run-b", TOKEN_B)]), Ok("run-b"));
    // The scheme is matched without regard to case, extra blanks are allowed.
    let loose = format!(
        "  bAsIc   {}  ",
        encode(format!("run-a:{TOKEN_A}").as_bytes())
    );
    assert_eq!(sessions.verify(&[loose]), Ok("run-a"));
}

#[test]
fn a_missing_wrong_or_borrowed_credential_is_refused() {
    let lookup = Fixed(HashMap::new());
    let sessions = two_sessions(&lookup);
    let none: [&str; 0] = [];
    assert_eq!(sessions.verify(&none), Err(AuthError::Missing));
    // Session A's token does not open session B, nor the other way round.
    assert_eq!(
        sessions.verify(&[header("run-b", TOKEN_A)]),
        Err(AuthError::Invalid)
    );
    assert_eq!(
        sessions.verify(&[header("run-a", TOKEN_B)]),
        Err(AuthError::Invalid)
    );
    assert_eq!(
        sessions.verify(&[header("run-c", TOKEN_A)]),
        Err(AuthError::Invalid)
    );
    let short = &TOKEN_A[..40];
    assert_eq!(
        sessions.verify(&[header("run-a", short)]),
        Err(AuthError::Invalid)
    );
    assert_eq!(
        sessions.verify(&[header("run-a", "")]),
        Err(AuthError::Invalid)
    );
}

#[test]
fn a_malformed_credential_is_refused() {
    let lookup = Fixed(HashMap::new());
    let sessions = two_sessions(&lookup);
    let valid = header("run-a", TOKEN_A);
    for bad in [
        "Basic".to_owned(),
        "Basic !!!!".to_owned(),
        format!("Bearer {}", encode(format!("run-a:{TOKEN_A}").as_bytes())),
        format!("Basic {}", encode(b"run-a")),
        format!("Basic {}=", encode(format!("run-a:{TOKEN_A}").as_bytes())),
        format!("run-a:{TOKEN_A}"),
    ] {
        assert_eq!(
            sessions.verify(std::slice::from_ref(&bad)),
            Err(AuthError::Malformed),
            "{bad}"
        );
    }
    // Two headers, even both valid, are ambiguous.
    assert_eq!(
        sessions.verify(&[valid.clone(), valid]),
        Err(AuthError::Malformed)
    );
}

#[test]
fn base64_decodes_with_and_without_padding() {
    assert_eq!(base64(b"eDp5").unwrap().as_slice(), b"x:y");
    assert_eq!(base64(b"eDp5eg==").unwrap().as_slice(), b"x:yz");
    assert_eq!(base64(b"eDp5eg").unwrap().as_slice(), b"x:yz");
    assert_eq!(base64(b"eDp5enc=").unwrap().as_slice(), b"x:yzw");
    assert!(base64(b"eDp5e").is_none());
    assert!(base64(b"eDp5eg=").is_none());
    assert!(base64(b"eDp-").is_none());
    assert!(base64(b"").is_none());
}

#[test]
fn equal_bytes_compare_equal_and_any_difference_does_not() {
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(TOKEN_A.as_bytes(), TOKEN_A.as_bytes()));
    let mut last = TOKEN_A.as_bytes().to_vec();
    *last.last_mut().unwrap() = b'b';
    assert!(!constant_time_eq(TOKEN_A.as_bytes(), &last));
    let mut first = TOKEN_A.as_bytes().to_vec();
    first[0] = b'b';
    assert!(!constant_time_eq(TOKEN_A.as_bytes(), &first));
    assert!(!constant_time_eq(
        TOKEN_A.as_bytes(),
        &TOKEN_A.as_bytes()[1..]
    ));
}

#[test]
fn credentials_refuse_ids_and_tokens_that_need_escaping() {
    assert!(Credential::new("run-1", TOKEN_A.as_bytes()).is_ok());
    for session in ["", "run a", "run:a", "run@a", "run/a", &"r".repeat(129)] {
        assert_eq!(
            Credential::new(session, TOKEN_A.as_bytes()).unwrap_err(),
            CredentialError::Session,
            "{session:?}"
        );
    }
    for token in [&TOKEN_A[..31], &format!("{}:", &TOKEN_A[..40])] {
        assert_eq!(
            Credential::new("run-1", token.as_bytes()).unwrap_err(),
            CredentialError::Token
        );
    }
}

#[test]
fn the_token_shows_only_in_the_proxy_url() {
    let credential = Credential::new("run-a", TOKEN_A.as_bytes()).unwrap();
    let debug = format!("{credential:?}");
    assert!(
        debug.contains("run-a") && !debug.contains(TOKEN_A),
        "{debug}"
    );
    let addr = SocketAddr::from(([127, 0, 0, 1], 4242));
    assert_eq!(
        credential.proxy_url(addr).as_str(),
        format!("http://run-a:{TOKEN_A}@127.0.0.1:4242")
    );
    let lookup = Fixed(HashMap::new());
    let sessions = two_sessions(&lookup);
    assert!(!format!("{sessions:?}").contains(TOKEN_A));
}

#[test]
fn taint_comes_from_the_lookup_for_that_session() {
    let read = Taint {
        secrets: vec![TaintSecret {
            source: "read ~/.config/x".to_owned(),
            host: None,
        }],
        untrusted: None,
    };
    let lookup = Fixed(HashMap::from([
        ("run-a", read.clone()),
        ("run-b", Taint::default()),
    ]));
    let sessions = two_sessions(&lookup);
    assert_eq!(sessions.taint("run-a"), Ok(read));
    assert_eq!(sessions.taint("run-b"), Ok(Taint::default()));
    assert!(sessions.taint("run-c").is_err());
}

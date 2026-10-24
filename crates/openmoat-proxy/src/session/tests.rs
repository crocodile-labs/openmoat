use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::{BuildHasher as _, Hasher as _, RandomState};
use std::sync::OnceLock;

use openmoat_core::TaintSecret;

use super::*;

/// A 64-character hex token made at run time, so no credential in these
/// tests is a fixed value: each `RandomState` is freshly keyed.
pub(crate) fn fresh_token() -> String {
    let mut token = String::new();
    for _ in 0..4 {
        let random = RandomState::new().build_hasher().finish();
        write!(token, "{random:016x}").unwrap();
    }
    token
}

/// Session `run-a`'s token, the same for the whole test run.
pub(crate) fn token_a() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(fresh_token)
}

/// Session `run-b`'s token, the same for the whole test run.
pub(crate) fn token_b() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(fresh_token)
}

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

/// Sessions `run-a` ([`token_a`]) and `run-b` ([`token_b`]).
pub(crate) fn two_sessions(lookup: &Fixed) -> Sessions<'_> {
    Sessions::new(
        vec![
            Credential::new("run-a", token_a().as_bytes()).unwrap(),
            Credential::new("run-b", token_b().as_bytes()).unwrap(),
        ],
        lookup,
    )
}

#[test]
fn fresh_tokens_are_valid_and_differ() {
    assert_eq!(token_a().len(), 64);
    assert_ne!(token_a(), token_b());
    assert!(Credential::new("run-a", token_a().as_bytes()).is_ok());
}

#[test]
fn a_valid_credential_names_its_own_session() {
    let lookup = Fixed(HashMap::new());
    let sessions = two_sessions(&lookup);
    assert_eq!(sessions.verify(&[header("run-a", token_a())]), Ok("run-a"));
    assert_eq!(sessions.verify(&[header("run-b", token_b())]), Ok("run-b"));
    // The scheme is matched without regard to case, extra blanks are allowed.
    let loose = format!(
        "  bAsIc   {}  ",
        encode(format!("run-a:{}", token_a()).as_bytes())
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
        sessions.verify(&[header("run-b", token_a())]),
        Err(AuthError::Invalid)
    );
    assert_eq!(
        sessions.verify(&[header("run-a", token_b())]),
        Err(AuthError::Invalid)
    );
    assert_eq!(
        sessions.verify(&[header("run-c", token_a())]),
        Err(AuthError::Invalid)
    );
    let short = &token_a()[..40];
    assert_eq!(
        sessions.verify(&[header("run-a", short)]),
        Err(AuthError::Invalid)
    );
    let empty = String::new();
    assert_eq!(
        sessions.verify(&[header("run-a", &empty)]),
        Err(AuthError::Invalid)
    );
}

#[test]
fn a_malformed_credential_is_refused() {
    let lookup = Fixed(HashMap::new());
    let sessions = two_sessions(&lookup);
    let valid = header("run-a", token_a());
    let pair = format!("run-a:{}", token_a());
    for bad in [
        "Basic".to_owned(),
        "Basic !!!!".to_owned(),
        format!("Bearer {}", encode(pair.as_bytes())),
        format!("Basic {}", encode(b"run-a")),
        format!("Basic {}=", encode(pair.as_bytes())),
        pair.clone(),
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
    let token = token_a().as_bytes();
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(token, token));
    // Flipping the lowest bit always changes the byte.
    let mut last = token.to_vec();
    *last.last_mut().unwrap() ^= 1;
    assert!(!constant_time_eq(token, &last));
    let mut first = token.to_vec();
    first[0] ^= 1;
    assert!(!constant_time_eq(token, &first));
    assert!(!constant_time_eq(token, &token[1..]));
}

#[test]
fn credentials_refuse_ids_and_tokens_that_need_escaping() {
    assert!(Credential::new("run-1", token_a().as_bytes()).is_ok());
    for session in ["", "run a", "run:a", "run@a", "run/a", &"r".repeat(129)] {
        assert_eq!(
            Credential::new(session, token_a().as_bytes()).unwrap_err(),
            CredentialError::Session,
            "{session:?}"
        );
    }
    for token in [&token_a()[..31], &format!("{}:", &token_a()[..40])] {
        assert_eq!(
            Credential::new("run-1", token.as_bytes()).unwrap_err(),
            CredentialError::Token
        );
    }
}

#[test]
fn the_token_shows_only_in_the_proxy_url() {
    let credential = Credential::new("run-a", token_a().as_bytes()).unwrap();
    let debug = format!("{credential:?}");
    assert!(
        debug.contains("run-a") && !debug.contains(token_a()),
        "{debug}"
    );
    let addr = SocketAddr::from(([127, 0, 0, 1], 4242));
    assert_eq!(
        credential.proxy_url(addr).as_str(),
        format!("http://run-a:{}@127.0.0.1:4242", token_a())
    );
    let lookup = Fixed(HashMap::new());
    let sessions = two_sessions(&lookup);
    assert!(!format!("{sessions:?}").contains(token_a()));
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

/// A taint that changes with the lookup's version, as the audit log grows.
struct Growing {
    version: std::sync::atomic::AtomicI64,
}

impl TaintLookup for Growing {
    fn taint(&self, _: &str) -> Result<Taint, String> {
        let n = self.version.load(std::sync::atomic::Ordering::SeqCst);
        Ok(Taint {
            secrets: (0..n)
                .map(|i| TaintSecret {
                    source: format!("read {i}"),
                    host: None,
                })
                .collect(),
            untrusted: None,
        })
    }

    fn version(&self) -> Option<i64> {
        Some(self.version.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[test]
fn a_recent_taint_is_looked_up_again_once_an_event_is_recorded() {
    let lookup = Growing { version: 0.into() };
    let sessions = Sessions::new(
        vec![Credential::new("run-a", token_a().as_bytes()).unwrap()],
        &lookup,
    );
    let long = Duration::from_hours(1);
    assert!(sessions.taint("run-a").unwrap().secrets.is_empty());
    // nothing new: the recent taint stands
    assert!(
        sessions
            .taint_within("run-a", long)
            .unwrap()
            .secrets
            .is_empty()
    );
    // the session read a secret: well within `max_age`, the taint is new
    lookup.version.store(1, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        sessions.taint_within("run-a", long).unwrap().secrets.len(),
        1
    );
}

/// A lookup whose version cannot be read (the audit log will not open), with a
/// taint a test can change or make fail.
struct Unversioned(std::sync::Mutex<Result<Taint, String>>);

impl TaintLookup for Unversioned {
    fn taint(&self, _: &str) -> Result<Taint, String> {
        self.0.lock().unwrap().clone()
    }
}

/// Without a version, a new event cannot be seen, so a recent taint is never
/// used again: the session's secret read is seen at once, and a history that
/// cannot be read then is an error (the proxy refuses), not the old taint.
#[test]
fn without_a_version_a_recent_taint_is_looked_up_again() {
    let lookup = Unversioned(std::sync::Mutex::new(Ok(Taint::default())));
    let sessions = Sessions::new(
        vec![Credential::new("run-a", token_a().as_bytes()).unwrap()],
        &lookup,
    );
    let long = Duration::from_hours(1);
    assert!(sessions.taint("run-a").unwrap().secrets.is_empty());
    *lookup.0.lock().unwrap() = Ok(Taint {
        secrets: vec![TaintSecret {
            source: "read ~/.ssh/id_rsa".to_owned(),
            host: None,
        }],
        untrusted: None,
    });
    assert_eq!(
        sessions.taint_within("run-a", long).unwrap().secrets.len(),
        1
    );
    *lookup.0.lock().unwrap() = Err("audit log unreadable".to_owned());
    assert!(sessions.taint_within("run-a", long).is_err());
}

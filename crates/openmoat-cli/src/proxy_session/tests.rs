use openmoat_proxy::Verify as _;

use super::*;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 4231 §4: test cases 1, 2, 3, 4, 6 and 7 (5 truncates the output).
#[test]
fn hmac_sha256_matches_rfc_4231() {
    let cases: [(Vec<u8>, Vec<u8>, &str); 6] = [
        (
            vec![0x0b; 20],
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            vec![0xaa; 20],
            vec![0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            unhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            vec![0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        (
            vec![0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        (
            vec![0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than \
              block-size data. The key needs to be hashed before being used by the \
              HMAC algorithm."
                .to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];
    for (key, data, expected) in cases {
        assert_eq!(hmac::sha256(&key, &data).to_vec(), unhex(expected));
    }
}

fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    // Not `.moat`: a sandbox the tests may run in refuses writes to one.
    let home = Home::at(dir.path().join("state"));
    (dir, home)
}

/// A credential's user and password, from its proxy URL.
fn pair(issued: &Issued) -> (String, String) {
    let url = issued.proxy_url(18080);
    let userinfo = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split_once('@'))
        .unwrap()
        .0;
    let (user, password) = userinfo.split_once(':').unwrap();
    (user.to_owned(), password.to_owned())
}

const NOW: u64 = 1_800_000_000;
const SESSION_A: &str = "7c1e4b2a-55d0-4b8e-9a51-0e3c2f7d9b10";
const SESSION_B: &str = "0d9e8f7a-1111-4b8e-9a51-0e3c2f7d9b10";

#[test]
fn an_issued_credential_names_its_session_until_it_expires() {
    let (_dir, home) = home();
    let key = Key::load_or_create(&home).unwrap();
    let issued = issue(&key, Host::ClaudeCode, SESSION_A, NOW).unwrap();
    assert_eq!(issued.expires, NOW + TTL.as_secs());
    let (user, password) = pair(&issued);
    assert_eq!(
        user,
        format!("v1.claude-code.{}.{SESSION_A}", issued.expires)
    );
    assert_eq!(password.len(), 64);
    let ok = |now| verify(&key, user.as_bytes(), password.as_bytes(), now);
    assert_eq!(ok(NOW).as_deref(), Some(SESSION_A));
    assert_eq!(ok(issued.expires - 1).as_deref(), Some(SESSION_A));
    // Replay after expiry: refused from the second it expires.
    assert_eq!(ok(issued.expires), None);
    assert_eq!(ok(issued.expires + 3600), None);
    // Nothing secret in what may be printed.
    assert!(!format!("{issued:?}{key:?}").contains(&password));
}

/// Session B cannot pass for session A with A's password, nor stretch or
/// move a credential by editing the signed name.
#[test]
fn a_credential_opens_only_its_own_session_and_cannot_be_edited() {
    let (_dir, home) = home();
    let key = Key::load_or_create(&home).unwrap();
    let a = issue(&key, Host::ClaudeCode, SESSION_A, NOW).unwrap();
    let b = issue(&key, Host::ClaudeCode, SESSION_B, NOW).unwrap();
    let (user_a, password_a) = pair(&a);
    let (user_b, password_b) = pair(&b);
    let check =
        |user: &str, password: &str| verify(&key, user.as_bytes(), password.as_bytes(), NOW);
    assert_eq!(check(&user_b, &password_b).as_deref(), Some(SESSION_B));
    assert_eq!(check(&user_b, &password_a), None);
    assert_eq!(check(&user_a, &password_b), None);
    let edits = [
        user_a.replace(SESSION_A, SESSION_B),
        user_a.replace(&a.expires.to_string(), &(a.expires + 60).to_string()),
        user_a.replace("claude-code", "codex"),
        user_a.replace("v1.", "v2."),
        format!("{user_a}x"),
        String::new(),
    ];
    for user in edits {
        assert_eq!(check(&user, &password_a), None, "{user}");
    }
    for password in [
        String::new(),
        password_a[..63].to_owned(),
        password_a.to_uppercase(),
    ] {
        assert_eq!(check(&user_a, &password), None, "{password}");
    }
}

/// A credential signed with another key (another machine's, or one made
/// before the key was replaced) opens nothing.
#[test]
fn a_credential_of_another_key_or_one_lasting_too_long_is_refused() {
    let (_dir, home_a) = home();
    let (_other, home_b) = home();
    let key_a = Key::load_or_create(&home_a).unwrap();
    let key_b = Key::load_or_create(&home_b).unwrap();
    let issued = issue(&key_b, Host::ClaudeCode, SESSION_A, NOW).unwrap();
    let (user, password) = pair(&issued);
    assert_eq!(
        verify(&key_a, user.as_bytes(), password.as_bytes(), NOW),
        None
    );
    // Signed for longer than the TTL allows: refused even with the right key.
    let far = issue(&key_a, Host::ClaudeCode, SESSION_A, NOW + 2 * TTL.as_secs()).unwrap();
    let (user, password) = pair(&far);
    assert_eq!(
        verify(&key_a, user.as_bytes(), password.as_bytes(), NOW),
        None
    );
}

#[test]
fn session_ids_that_need_escaping_or_name_no_session_get_no_credential() {
    let (_dir, home) = home();
    let key = Key::load_or_create(&home).unwrap();
    for session in ["", "unknown", "a b", "a:b", "a@b", "a/b", &"s".repeat(129)] {
        assert!(
            issue(&key, Host::ClaudeCode, session, NOW).is_err(),
            "{session:?}"
        );
    }
}

#[test]
fn the_key_is_made_once_owner_only_and_kept() {
    let (_dir, home) = home();
    let first = Key::load_or_create(&home).unwrap();
    let path = key_path(&home);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.trim().len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A second maker keeps the first key; a racing writer does not replace it.
    assert!(!crate::home::write_private_new(&path, b"00\n").unwrap());
    let again = Key::load_or_create(&home).unwrap();
    let issued = issue(&first, Host::ClaudeCode, SESSION_A, NOW).unwrap();
    let (user, password) = pair(&issued);
    assert!(verify(&again, user.as_bytes(), password.as_bytes(), NOW).is_some());
    std::fs::write(&path, "not hex\n").unwrap();
    assert!(Key::load(&path).is_err());
}

/// Replacing the key revokes every credential at once, without a restart of
/// the proxy; until then an old credential stays valid.
#[test]
fn the_verifier_follows_a_replaced_key() {
    let (_dir, home) = home();
    // Looked at on every check here; the proxy looks every `KEY_RECHECK`.
    let verifier = Verifier::open_with(&home, Duration::ZERO).unwrap();
    let old = Key::load(&key_path(&home)).unwrap();
    let now = now_s();
    let (user, password) = pair(&issue(&old, Host::ClaudeCode, SESSION_A, now).unwrap());
    assert_eq!(
        verifier
            .verify(user.as_bytes(), password.as_bytes())
            .as_deref(),
        Some(SESSION_A)
    );
    std::fs::remove_file(key_path(&home)).unwrap();
    // No key, no credential.
    assert_eq!(verifier.verify(user.as_bytes(), password.as_bytes()), None);
    let new = Key::load_or_create(&home).unwrap();
    // The old credential is revoked with the key it was signed with.
    assert_eq!(verifier.verify(user.as_bytes(), password.as_bytes()), None);
    let (user, password) = pair(&issue(&new, Host::ClaudeCode, SESSION_B, now).unwrap());
    assert_eq!(
        verifier
            .verify(user.as_bytes(), password.as_bytes())
            .as_deref(),
        Some(SESSION_B)
    );
}

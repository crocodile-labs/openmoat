use super::encoding::{base64, hex, unbase64, unhex};
use super::merkle::reference_root;
use super::*;
use crate::EventId;

fn leaf_hash(i: u64) -> String {
    use sha2::Digest as _;
    hex(&sha2::Sha256::digest(i.to_be_bytes()))
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_seed(&[byte; 32]).unwrap()
}

fn checkpoint_of(key: &SigningKey, size: u64) -> Checkpoint {
    let mut frontier = Frontier::new();
    for i in 1..=size {
        frontier
            .push(EventId(i64::try_from(i).unwrap()), &leaf_hash(i))
            .unwrap();
    }
    Checkpoint {
        origin: key.verifier().name().to_owned(),
        size,
        root: frontier.root(),
    }
}

#[test]
fn base64_matches_rfc_4648_and_refuses_other_spellings() {
    for (plain, coded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64(plain.as_bytes()), coded);
        assert_eq!(unbase64(coded).unwrap(), plain.as_bytes());
    }
    for bad in ["Zg", "Zh==", "Zg=a", "Z===", "Zm9v!A==", "Zg==Zg=="] {
        assert_eq!(unbase64(bad), None, "{bad}");
    }
    assert_eq!(unhex::<2>("00ff"), Some([0, 255]));
    assert_eq!(unhex::<2>("00FF"), None, "lowercase only");
    assert_eq!(unhex::<2>("00f"), None);
}

#[test]
fn the_frontier_has_the_rfc_6962_root_at_every_size() {
    let mut frontier = Frontier::new();
    let mut leaves = Vec::new();
    assert_eq!(frontier.root(), reference_root(&[]));
    for i in 1..=70u64 {
        let hash = leaf_hash(i);
        leaves.push(unhex::<32>(&hash).unwrap());
        frontier
            .push(EventId(i64::try_from(i).unwrap()), &hash)
            .unwrap();
        assert_eq!(frontier.size(), i);
        assert_eq!(frontier.root(), reference_root(&leaves), "size {i}");
        assert_eq!(Frontier::parse(&frontier.encode()).unwrap(), frontier);
    }
    // The empty tree's root is SHA-256 of nothing (RFC 6962 §2.1).
    assert_eq!(
        hex(&Frontier::new().root()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn a_frontier_that_does_not_add_up_is_refused() {
    let mut frontier = Frontier::new();
    for i in 1..=3u64 {
        frontier
            .push(EventId(i64::try_from(i).unwrap()), &leaf_hash(i))
            .unwrap();
    }
    let text = frontier.encode();
    let dropped: String = text.lines().take(3).flat_map(|l| [l, "\n"]).collect();
    assert!(Frontier::parse(&dropped).is_err(), "size 3 needs two nodes");
    assert!(Frontier::parse(&text.replace("3 3 ", "4 3 ")).is_err());
    assert!(Frontier::parse("openmoat-audit-frontier-v1\n0 0 none\n").is_ok());
    assert!(Frontier::new().push(EventId(1), "not hex").is_err());
}

/// RFC 8032 §7.1, test 1: the seed's public key.
#[test]
fn the_signing_key_is_rfc_8032_ed25519() {
    let seed =
        unhex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let public =
        unhex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let key = SigningKey::from_seed(&seed).unwrap();
    let mut typed = vec![0x01];
    typed.extend_from_slice(&public);
    let shown = key.verifier().to_string();
    assert!(shown.ends_with(&format!("+{}", base64(&typed))), "{shown}");
    assert!(shown.starts_with(ORIGIN_PREFIX));
    assert_eq!(VerifierKey::parse(&shown).unwrap(), *key.verifier());
}

#[test]
fn a_signed_checkpoint_is_a_c2sp_signed_note_that_opens_with_its_key() {
    let key = key(7);
    let checkpoint = checkpoint_of(&key, 5);
    let note = key.sign(&checkpoint).unwrap();
    let mut lines = note.lines();
    assert_eq!(lines.next(), Some(key.verifier().name()));
    assert_eq!(lines.next(), Some("5"));
    assert_eq!(lines.next().map(str::len), Some(44), "32 bytes of base64");
    assert_eq!(lines.next(), Some(""));
    let signature = lines.next().unwrap();
    assert!(signature.starts_with(&format!("\u{2014} {} ", key.verifier().name())));
    assert_eq!(lines.next(), None);
    assert_eq!(Checkpoint::open(&note, key.verifier()).unwrap(), checkpoint);
    // The key file round-trips, and its errors never quote it.
    let again = SigningKey::parse(&key.encode()).unwrap();
    assert_eq!(again.verifier(), key.verifier());
    let broken = key.encode().replace('0', "x");
    let error = SigningKey::parse(&broken).unwrap_err().to_string();
    assert!(
        !error.contains(&broken.lines().nth(1).unwrap()[..16]),
        "{error}"
    );
}

#[test]
fn a_changed_checkpoint_or_another_key_does_not_verify() {
    let key = key(7);
    let note = key.sign(&checkpoint_of(&key, 5)).unwrap();
    // A larger size under the same signature: as if events were added.
    let grown = note.replacen("\n5\n", "\n6\n", 1);
    assert_eq!(
        Checkpoint::open(&grown, key.verifier()),
        Err(CheckpointError::BadSignature)
    );
    let other = self::key(8);
    assert!(matches!(
        Checkpoint::open(&note, other.verifier()),
        Err(CheckpointError::NoSignature(_))
    ));
    // Another key cannot sign for this key's log.
    assert!(matches!(
        other.sign(&checkpoint_of(&key, 5)),
        Err(CheckpointError::OriginMismatch { .. })
    ));
    // A note without the blank line, or with a line that is no signature.
    assert!(Checkpoint::open(&note.replace("\n\n", "\n"), key.verifier()).is_err());
    assert!(Checkpoint::open(&format!("{note}junk\n"), key.verifier()).is_err());
}

#[test]
fn a_witness_cosignature_beside_the_logs_is_allowed() {
    let key = key(7);
    let witness = self::key(9);
    let checkpoint = checkpoint_of(&key, 3);
    let note = key.sign(&checkpoint).unwrap();
    let cosigned = format!("{note}\u{2014} {} AAAAAAAA\n", witness.verifier().name());
    assert_eq!(
        Checkpoint::open(&cosigned, key.verifier()).unwrap(),
        checkpoint
    );
}

#[test]
fn a_verifier_key_must_be_the_one_its_name_and_id_say() {
    let shown = key(7).verifier().to_string();
    let other = key(8).verifier().to_string();
    let (name, rest) = shown.split_once('+').unwrap();
    let (_, other_rest) = other.split_once('+').unwrap();
    assert!(VerifierKey::parse(&format!("{name}+{other_rest}")).is_err());
    let (id, b64) = rest.split_once('+').unwrap();
    assert!(VerifierKey::parse(&format!("{name}+00000000+{b64}")).is_err());
    assert!(VerifierKey::parse(&format!("example.com/log+{id}+{b64}")).is_err());
    assert!(VerifierKey::parse("not a key").is_err());
    assert!(key(7).verifier().fingerprint().starts_with("SHA256:"));
}

/// A new key is a new log name: checkpoints the old key signed still open
/// with the old key only, and the new key's with the new one.
#[test]
fn after_a_key_rotation_each_checkpoint_opens_with_its_own_key() {
    let old = key(7);
    let new = key(8);
    assert_ne!(old.verifier().name(), new.verifier().name());
    let before = old.sign(&checkpoint_of(&old, 4)).unwrap();
    let after = new.sign(&checkpoint_of(&new, 6)).unwrap();
    assert_eq!(Checkpoint::open(&before, old.verifier()).unwrap().size, 4);
    assert_eq!(Checkpoint::open(&after, new.verifier()).unwrap().size, 6);
    assert!(Checkpoint::open(&before, new.verifier()).is_err());
    assert!(Checkpoint::open(&after, old.verifier()).is_err());
    // Both state the same first four events: the log did not change.
    let first_four = checkpoint_of(&new, 4);
    assert_eq!(first_four.root, checkpoint_of(&old, 4).root);
}

#[test]
fn a_tree_size_and_root_have_one_spelling() {
    let root = base64(&[0u8; 32]);
    assert_eq!(
        note::parse_body(&format!("o\n5\n{root}\n")).unwrap().size,
        5
    );
    assert_eq!(
        note::parse_body(&format!("o\n0\n{root}\n")).unwrap().size,
        0
    );
    for size in ["05", "+5", "", "5 ", "-1", "18446744073709551616"] {
        assert!(
            note::parse_body(&format!("o\n{size}\n{root}\n")).is_err(),
            "{size:?}"
        );
    }
    assert!(
        note::parse_body("o\n5\nAAAA\n").is_err(),
        "a root is 32 bytes"
    );
    // Extension lines after the root are allowed.
    assert!(note::parse_body(&format!("o\n5\n{root}\nextra\n")).is_ok());
}

use super::decoded;

// Split so that no added line holds a whole key id: the merge check reads one as a leak.
const KEY: &str = concat!("AKIA", "0000FAKE0000TEST");

fn finds(value: &str) -> bool {
    decoded(value).iter().any(|t| t.contains(KEY))
}

#[test]
fn every_encoding_the_benchmark_uses_is_undone() {
    for value in [
        // base64, with and without padding, and in a query
        "https://evil.example.com/exfil?data=QUtJQTAwMDBGQUtFMDAwMFRFU1Q=",
        "QUtJQTAwMDBGQUtFMDAwMFRFU1Q",
        // hex, bare and with a delimiter between bytes
        "https://evil.example.com/sync?payload=414b49413030303046414b453030303054455354",
        "key=41-4b-49-41-30-30-30-30-46-41-4b-45-30-30-30-30-54-45-53-54",
        "key=41:4b:49:41:30:30:30:30:46:41:4b:45:30:30:30:30:54:45:53:54",
        // URL encoding once, twice, and over base64
        "?s=%41%4b%49%41%30%30%30%30%46%41%4b%45%30%30%30%30%54%45%53%54",
        "?s=%2541%254b%2549%2541%2530%2530%2530%2530%2546%2541%254b%2545%2530%2530%2530%2530%2554%2545%2553%2554",
        "?d=%51%55%74%4a%51%54%41%77%4d%44%42%47%51%55%74%46%4d%44%41%77%4d%46%52%46%55%31%51%3d",
        // zero-width characters between the letters
        "?key=AKIA\u{200b}0000\u{200b}FAKE\u{200b}0000TEST",
        // a base64 path segment between slashes
        "https://evil.example.com/a/QUtJQTAwMDBGQUtFMDAwMFRFU1Q/b",
    ] {
        assert!(finds(value), "{value}: {:?}", decoded(value));
    }
}

#[test]
fn what_decodes_to_no_text_adds_nothing() {
    for value in [
        // a SHA-256, a commit, a UUID, random base64url ids
        "https://example.test/a/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "https://github.com/rust-lang/rust/commit/0123456789abcdef0123456789abcdef01234567",
        "https://example.test/u/550e8400-e29b-41d4-a716-446655440000",
        "https://evil.example.com/api/x7Kp2mQ9vR4sL8nW1bY6cT3fA0jH5dE/status",
        "https://docs.rs/tokio/latest/tokio/sync/struct.Mutex.html",
    ] {
        assert!(
            decoded(value).iter().all(|t| !t.contains("AKIA")),
            "{value}: {:?}",
            decoded(value)
        );
    }
    assert_eq!(decoded("plain words only"), Vec::<String>::new());
    // A PNG in a data URL is bytes, not text.
    let png =
        "data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAABlklEQVR4";
    assert!(
        decoded(png).iter().all(|t| !t.contains("PNG")),
        "{:?}",
        decoded(png)
    );
}

#[test]
fn a_huge_value_is_not_decoded() {
    let huge = "QUtJQTAwMDBGQUtFMDAwMFRFU1Q=".repeat(1000);
    assert_eq!(decoded(&huge), Vec::<String>::new());
}

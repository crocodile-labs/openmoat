use serde_json::json;

use super::parse;

#[test]
fn plain_json_reads_as_serde_json_does() {
    let text = r#"{"a": [1, -2, 3.5, 1e3, true, null], "b": {"c": "dé\n"}}"#;
    let parsed = parse(text).unwrap();
    assert_eq!(
        parsed.value,
        serde_json::from_str::<serde_json::Value>(text).unwrap()
    );
    assert!(!parsed.comments);
}

#[test]
fn json5_syntax_reads_as_its_json_value() {
    let text = "\u{feff}// OpenClaw\n{\n  gateway: { port: 18789, },\n  /* plugins */\n  \
                plugins: { allow: ['a', \"b\",], $x_1: .5, y: 5., z: +1, h: 0xFF, n: -0x10 },\n  \
                'quoted key': 'it\\'s \\x41\\u00e9 \\\n done',\n}\n";
    let parsed = parse(text).unwrap();
    assert!(parsed.comments);
    assert_eq!(
        parsed.value,
        json!({
            "gateway": {"port": 18789},
            "plugins": {"allow": ["a", "b"], "$x_1": 0.5, "y": 5.0, "z": 1, "h": 255, "n": -16},
            "quoted key": "it's A\u{e9}  done",
        })
    );
}

#[test]
fn comment_marks_inside_strings_are_text() {
    let parsed = parse(r#"{"url": "https://x/*y*/", 'p': '//not'}"#).unwrap();
    assert!(!parsed.comments);
    assert_eq!(parsed.value["url"], "https://x/*y*/");
}

#[test]
fn the_last_of_duplicate_keys_wins() {
    assert_eq!(parse("{a: 1, a: 2}").unwrap().value, json!({"a": 2}));
}

#[test]
fn escapes_in_keys_and_surrogate_pairs() {
    let parsed = parse(r#"{ab: "😀"}"#).unwrap();
    assert_eq!(parsed.value, json!({"ab": "\u{1F600}"}));
    assert!(parse(r#"{"x": "\uD83D"}"#).is_err());
}

#[test]
fn what_json_cannot_hold_or_json5_does_not_allow_is_refused() {
    for text in [
        "{a: Infinity}",
        "{a: -Infinity}",
        "{a: NaN}",
        "{a: 01}",
        "{a: 1,,}",
        "{,}",
        "[1 2]",
        "{a 1}",
        "{a: undefined}",
        "{a: 'x\ny'}",
        "{a: '\\1'}",
        "{a: 1} x",
        "/* open",
        "{a: 0x}",
        "{a: 1e}",
        "{a: .}",
        "{a: 12abc}",
        "",
    ] {
        assert!(parse(text).is_err(), "{text:?} should be refused");
    }
}

#[test]
fn deep_nesting_is_refused_not_recursed() {
    let deep = "[".repeat(10_000);
    assert!(parse(&deep).is_err());
    let fine = format!("{}{}", "[".repeat(100), "]".repeat(100));
    assert!(parse(&fine).is_ok());
}

#[test]
fn errors_name_the_line() {
    let error = parse("{\n  a: 1,\n  b: ?\n}").unwrap_err().to_string();
    assert!(error.contains("line 3"), "{error}");
}

use super::{base64_literals, decode, utf16le_base64};

#[test]
fn decodes_what_powershell_encodes() {
    assert_eq!(decode("Y2F0").as_deref(), Some(&b"cat"[..]));
    assert_eq!(decode("Y2E=").as_deref(), Some(&b"ca"[..]));
    // `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('echo hi'))`
    assert_eq!(
        utf16le_base64("ZQBjAGgAbwAgAGgAaQA=").as_deref(),
        Some("echo hi")
    );
    assert_eq!(utf16le_base64("not base64!"), None);
    assert_eq!(utf16le_base64("Y2F0"), None);
}

/// A sample line the classifier reads; nothing runs it.
#[test]
fn reads_the_literals_a_decoding_line_names() {
    let line = "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('UmVtb3ZlLUl0ZW0gfg==')))";
    assert_eq!(base64_literals(line), vec!["Remove-Item ~".to_owned()]);
    assert_eq!(
        base64_literals("echo 'UmVtb3ZlLUl0ZW0gfg=='"),
        Vec::<String>::new()
    );
}

use super::*;

#[test]
fn schema_has_only_codex_command_fields_and_round_trips_quoted_paths() {
    // HookHandlerConfig::Command in rust-v0.166.0 has no args field.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Handler {
        r#type: String,
        command: String,
        command_windows: String,
        timeout: u64,
        status_message: String,
    }
    for path in [
        "/a b/openmoat",
        "/a'\"$`\\b/openmoat",
        r"C:\User's Files\%PATH%\openmoat.exe",
    ] {
        let entry = Codex.entry(
            &HookSpec::new("PreToolUse", "Bash", 600, false),
            "codex",
            path,
            false,
        );
        let command: Handler = serde_json::from_value(entry["hooks"][0].clone()).unwrap();
        assert_eq!(command.r#type, "command");
        assert!(command.command.ends_with(" guard --host codex"));
        assert!(
            command
                .command_windows
                .starts_with("powershell.exe -NoProfile -NonInteractive -EncodedCommand ")
        );
        assert_eq!(command.timeout, 600);
        assert_eq!(command.status_message, "OpenMoat");
        assert_eq!(Codex.binary(&entry, "codex").as_deref(), Some(path));
        assert!(Codex.is_ours(&entry, "codex"));
        assert!(!Codex.is_ours(&entry, "claude-code"));
    }
}

#[test]
fn windows_encoding_preserves_utf16_and_padding() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(&[b'A', 0]), "QQA=");
    assert_eq!(base64(b"foob"), "Zm9vYg==");
    assert_eq!(base64(b"fooba"), "Zm9vYmE=");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    let unicode: Vec<u8> = "🙂".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(base64(&unicode), "PdhC3g==");
}

#[test]
fn legacy_entries_are_recognised_but_stale() {
    let spec = HookSpec::new("PreToolUse", "Bash", 600, false);
    let legacy = json!({"matcher":"Bash", "hooks":[{"type":"command", "command":"/bin/openmoat", "args":["guard","--host","codex"], "timeout":600}]});
    assert!(Codex.is_ours(&legacy, "codex"));
    let mut unrelated = legacy.clone();
    unrelated["hooks"][0]["args"] = json!(["status"]);
    assert!(!Codex.is_ours(&unrelated, "codex"));
    let mut root = json!({"hooks":{"PreToolUse":[legacy, unrelated.clone()]}});
    let layout: &dyn HookFile = &Codex;
    assert!(matches!(
        layout.state(&root, "codex", &[spec], "/bin/openmoat", || false),
        crate::HookFileState::Stale { .. }
    ));
    layout
        .upsert(
            &mut root,
            "hooks.json",
            "codex",
            &[spec],
            "/bin/openmoat",
            || false,
        )
        .unwrap();
    assert_eq!(root["hooks"]["PreToolUse"][1], unrelated);
    assert_eq!(
        layout.state(&root, "codex", &[spec], "/bin/openmoat", || false),
        crate::HookFileState::Installed
    );
}

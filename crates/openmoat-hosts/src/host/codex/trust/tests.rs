use super::*;

fn normalised_hash(bytes: &[u8]) -> String {
    let command = if cfg!(windows) {
        "windows hook"
    } else {
        "posix hook"
    };
    assert_eq!(
        serde_json::from_slice::<Value>(bytes).unwrap(),
        json!({
            "event_name":"pre_tool_use", "matcher":"Bash",
            "hooks":[{"type":"command", "command":command, "timeout":600,
                "async":false, "statusMessage":"OpenMoat"}]
        })
    );
    "expected".to_owned()
}

fn hooks() -> Value {
    let mut entry = super::super::hook_file::Codex.entry(
        &crate::HookSpec::new("PreToolUse", "Bash", 600, false),
        "codex",
        "openmoat",
        false,
    );
    // Keep the guard suffix for ownership detection, with separate values
    // below to verify the platform command selection during normalisation.
    entry["hooks"][0]["commandWindows"] = json!("windows hook");
    json!({"hooks":{"PreToolUse":[entry]}})
}

fn digest(bytes: &[u8]) -> String {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    if !cfg!(windows) {
        assert_eq!(
            value["hooks"][0]["command"],
            "'openmoat' guard --host codex"
        );
        value["hooks"][0]["command"] = json!("posix hook");
    }
    normalised_hash(&serde_json::to_vec(&value).unwrap())
}

#[test]
fn a_matching_enabled_record_has_no_advisory() {
    let state =
        json!({"hooks":{"state":{"source:pre_tool_use:0:0":{"trusted_hash":"sha256:expected"}}}});
    assert_eq!(Codex.warning(&hooks(), &state, "source", digest), None);
}

#[test]
fn absent_stale_disabled_and_wrong_source_records_warn() {
    for state in [
        Value::Null,
        json!({"hooks":{"state":{"source:pre_tool_use:0:0":{"trusted_hash":"sha256:old"}}}}),
        json!({"hooks":{"state":{"source:pre_tool_use:0:0":{"trusted_hash":"sha256:expected", "enabled":false}}}}),
        json!({"hooks":{"state":{"other:pre_tool_use:0:0":{"trusted_hash":"sha256:expected"}}}}),
    ] {
        assert!(Codex.warning(&hooks(), &state, "source", digest).is_some());
    }
}

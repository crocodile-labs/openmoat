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
        &crate::GuardCommand::new("openmoat"),
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

/// The hash of an identity, as its event's name: enough to tell the two apart.
fn by_event(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).unwrap();
    value["event_name"].as_str().unwrap().to_owned()
}

/// Once `init` added the `PostToolUse` entry (ADR-063), it must be trusted too.
#[test]
fn an_after_call_entry_needs_its_own_trust() {
    let entry = |event| {
        super::super::hook_file::Codex.entry(
            &crate::HookSpec::new(event, "Bash", 600, false),
            "codex",
            &crate::GuardCommand::new("openmoat"),
            false,
        )
    };
    let hooks = json!({"hooks":{
        "PreToolUse":[entry("PreToolUse")],
        "PostToolUse":[entry("PostToolUse")],
    }});
    let pre = json!({"trusted_hash":"sha256:pre_tool_use"});
    let post = json!({"trusted_hash":"sha256:post_tool_use"});
    let only_pre = json!({"hooks":{"state":{"source:pre_tool_use:0:0": pre}}});
    assert!(Codex.warning(&hooks, &only_pre, "source", by_event).is_some());
    let both = json!({"hooks":{"state":{
        "source:pre_tool_use:0:0": pre, "source:post_tool_use:0:0": post,
    }}});
    assert_eq!(Codex.warning(&hooks, &both, "source", by_event), None);
}

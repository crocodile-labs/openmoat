//! What a `Write` and an `Edit` carry: the content, or the replacements.

use crate::Host;

/// File provenance (ADR-029) hashes what `Write` writes; a partial edit has
/// no whole content to hash.
#[test]
fn only_a_whole_file_write_carries_its_content() {
    let parse = |tool: &str, input: serde_json::Value| {
        let payload = serde_json::json!({
            "session_id": "s", "cwd": "/p", "tool_name": tool, "tool_input": input
        });
        Host::ClaudeCode
            .parse_request(&payload.to_string())
            .unwrap()
            .content
    };
    let write = serde_json::json!({"file_path": "/p/run.sh", "content": "echo hi\n"});
    assert_eq!(parse("Write", write).as_deref(), Some("echo hi\n"));
    let empty = serde_json::json!({"file_path": "/p/run.sh", "content": ""});
    assert_eq!(parse("Write", empty).as_deref(), Some(""));
    let edit = serde_json::json!({"file_path": "/p/run.sh", "old_string": "a", "new_string": "b"});
    assert_eq!(parse("Edit", edit), None);
    assert_eq!(parse("Bash", serde_json::json!({"command": "ls"})), None);
}

/// A partial edit carries its replacements instead (ADR-048): `Edit`'s one,
/// each of `MultiEdit`'s in order; an entry without its strings is dropped,
/// and every other tool carries none.
#[test]
fn a_partial_edit_carries_its_replacements() {
    let parse = |tool: &str, input: serde_json::Value| {
        let payload = serde_json::json!({
            "session_id": "s", "cwd": "/p", "tool_name": tool, "tool_input": input
        });
        Host::ClaudeCode
            .parse_request(&payload.to_string())
            .unwrap()
            .edits
    };
    let replacement = |old: &str, new: &str, all| crate::Replacement {
        old: old.to_owned(),
        new: new.to_owned(),
        all,
    };
    let edit = serde_json::json!({"file_path": "/p/x.md", "old_string": "a", "new_string": "b"});
    assert_eq!(parse("Edit", edit), [replacement("a", "b", false)]);
    let everywhere = serde_json::json!({
        "file_path": "/p/x.md", "old_string": "a", "new_string": "b", "replace_all": true
    });
    assert_eq!(parse("Edit", everywhere), [replacement("a", "b", true)]);
    let multi = serde_json::json!({"file_path": "/p/x.md", "edits": [
        {"old_string": "a", "new_string": "b"},
        {"old_string": "c", "new_string": "d", "replace_all": true},
        {"old_string": "no new string"}
    ]});
    assert_eq!(
        parse("MultiEdit", multi),
        [replacement("a", "b", false), replacement("c", "d", true)]
    );
    let write = serde_json::json!({"file_path": "/p/x.md", "content": "a"});
    assert!(parse("Write", write).is_empty());
    assert!(parse("Bash", serde_json::json!({"command": "ls"})).is_empty());
}

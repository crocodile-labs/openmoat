use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;
use crate::integrity::HookPins;

/// A state directory and a config directory recorded for `host`, with `file`
/// holding `text`.
fn host_with_file(host: Host, file: &str, text: &str) -> (tempfile::TempDir, Home, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    let cfg = dir.path().join("agent");
    fs::create_dir_all(&cfg).unwrap();
    let mut recorded = Recorded::default();
    recorded.dirs.insert(host.id().to_owned(), cfg.clone());
    recorded.save(&home).unwrap();
    let path = cfg.join(file);
    fs::write(&path, text).unwrap();
    (dir, home, path)
}

/// `hosts.json` holds the record, and no lock is needed for the flow.
#[test]
fn an_opencode_list_is_wrapped_backed_up_shown_and_undone() {
    let text = r#"{"theme": "x", "mcp": {"db": {"type": "local", "command": ["db-mcp", "-v"]},
        "web": {"type": "remote", "url": "https://example.invalid"}}}"#;
    let (_dir, home, file) = host_with_file(Host::OpenCode, "opencode.json", text);
    let binary = Path::new("/x/openmoat");
    let hosts = [Host::OpenCode];

    let mut out = Deferred::default();
    let names = ["db".to_owned()];
    let shown = wrap_servers(&home, binary, &hosts, &names, Some(false), true, &mut out).unwrap();
    assert_eq!(shown, 1);
    assert_eq!(fs::read_to_string(&file).unwrap(), text, "a dry run");

    let done = wrap_servers(&home, binary, &hosts, &names, Some(false), false, &mut out).unwrap();
    assert_eq!(done, 1);
    let doc: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(doc["theme"], "x", "the rest of the file stays");
    assert_eq!(doc["mcp"]["web"]["url"], "https://example.invalid");
    let line = doc["mcp"]["db"]["command"].as_array().unwrap();
    assert_eq!(line[0], "/x/openmoat");
    assert_eq!(line[line.len() - 2..], ["db-mcp", "-v"]);
    assert_eq!(doc["mcp"]["db"].get("args"), None);
    let backups: Vec<_> = fs::read_dir(file.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(wrap::MCP_BACKUP))
        .collect();
    assert_eq!(backups.len(), 1, "{backups:?}");

    assert_eq!(unwrap_servers(&home, &hosts, &[], &mut out).unwrap(), 1);
    let doc: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(
        doc["mcp"]["db"],
        json!({"type": "local", "command": ["db-mcp", "-v"]})
    );
}

/// A YAML file is not guessed at: each server is named with what to set by
/// hand, under goose's own key, and nothing is written or recorded.
#[test]
fn a_goose_server_is_named_with_what_to_set_by_hand_and_the_file_stays() {
    let text = "extensions:\n  gh:\n    enabled: true\n    type: stdio\n    name: gh\n    \
                cmd: npx\n    args: [\"-y\", \"pkg\"]\n  snake:\n    enabled: true\n    \
                type: inline_python\n    name: snake\n    code: print(1)\n";
    let (_dir, home, file) = host_with_file(Host::Goose, "config.yaml", text);
    let mut out = Deferred::quiet();
    let binary = Path::new("/x/openmoat");
    let hosts = [Host::Goose];
    let edits = wrap_plan(&home, binary, &hosts, &[], Some(false), &mut out).unwrap();
    assert_eq!(edits.len(), 1, "the stdio extension, not the inline Python");
    let previews = wrap::preview(&edits);
    let said = previews[0].change.as_ref().unwrap_err();
    assert!(said.contains("is YAML"), "{said}");
    assert!(said.contains("gh: cmd: \"/x/openmoat\""), "{said}");
    let named = wrap_servers(&home, binary, &hosts, &[], Some(false), false, &mut out).unwrap();
    assert_eq!(named, 1, "named, not wrapped");
    assert_eq!(fs::read_to_string(&file).unwrap(), text);
    assert_eq!(Recorded::load(&home).unwrap().mcp_wrapped, Vec::new());
}

/// A comment OpenMoat would lose is named, and the others are still wrapped.
#[test]
fn an_opencode_file_with_comments_is_named_and_left() {
    let text =
        "{\n  // mine\n  \"mcp\": {\"db\": {\"type\": \"local\", \"command\": [\"db\"]}}\n}\n";
    let (_dir, home, file) = host_with_file(Host::OpenCode, "opencode.jsonc", text);
    let mut out = Deferred::default();
    let hosts = [Host::OpenCode];
    let binary = Path::new("/x/openmoat");
    wrap_servers(&home, binary, &hosts, &[], Some(false), false, &mut out).unwrap();
    assert_eq!(fs::read_to_string(&file).unwrap(), text);
    assert_eq!(Recorded::load(&home).unwrap().mcp_wrapped, Vec::new());
}

#[test]
fn wrapping_re_pins_what_it_wrote_and_nothing_else_drifts() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    let cfg = dir.path().join("claude");
    fs::create_dir_all(&cfg).unwrap();
    let mut recorded = Recorded::default();
    recorded
        .dirs
        .insert(Host::ClaudeCode.id().to_owned(), cfg.clone());
    recorded.save(&home).unwrap();
    let file = cfg.join(".claude.json");
    fs::write(
        &file,
        r#"{"mcpServers": {"gh": {"command": "npx"}, "db": {"command": "db"}}}"#,
    )
    .unwrap();
    let binary = Path::new("/x/moat");
    // The lock pins `hosts.json`, as `moat init` leaves it, and both servers.
    integrity::repin(&home, binary, HookPins::Adopt).unwrap();
    let lock = Lock::load(&home.lock_path()).unwrap();
    assert!(lock.pins(&home.hosts_path()));
    let found = mcp::review(&home, &lock, &[Host::ClaudeCode], None).unwrap();
    mcp::accept(&home, &found.changes).unwrap();

    let mut out = Deferred::default();
    let names = ["gh".to_owned()];
    let done = wrap_servers(
        &home,
        binary,
        &[Host::ClaudeCode],
        &names,
        Some(false),
        false,
        &mut out,
    )
    .unwrap();
    assert_eq!(done, 1);
    assert!(fs::read_to_string(&file).unwrap().contains("proxy"));
    assert!(
        Recorded::load(&home).unwrap().mcp_wrapped.len() == 1,
        "the wrap is recorded in hosts.json"
    );
    assert_eq!(
        integrity::violation(&home).unwrap(),
        None,
        "hosts.json was re-pinned"
    );
    let lock = crate::integrity::Lock::load(&home.lock_path()).unwrap();
    for tool in ["mcp__gh__search", "mcp__db__query"] {
        assert_eq!(
            mcp::violation(&home, &lock, Host::ClaudeCode, None, tool).unwrap(),
            None,
            "{tool}"
        );
    }
}

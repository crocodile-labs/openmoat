use std::fs;

use super::*;
use crate::integrity::HookPins;

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
        false,
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
    for tool in ["mcp__gh__search", "mcp__db__query"] {
        assert_eq!(
            mcp::violation(&home, Host::ClaudeCode, None, tool).unwrap(),
            None,
            "{tool}"
        );
    }
}

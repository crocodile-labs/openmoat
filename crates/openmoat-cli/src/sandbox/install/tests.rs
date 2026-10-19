use super::*;

#[test]
fn claude_code_and_cursor_on_native_windows_go_without_a_sandbox() {
    assert!(unavailable_on(Host::ClaudeCode, true).is_some_and(|n| n.contains("WSL2")));
    assert_eq!(unavailable_on(Host::Codex, true), None);
    assert_eq!(unavailable_on(Host::ClaudeCode, false), None);
    assert!(unavailable_on(Host::Cursor, true).is_some());
    assert_eq!(unavailable_on(Host::Cursor, false), None);
    assert_eq!(unavailable(Host::ClaudeCode).is_some(), cfg!(windows));
}

#[test]
fn claude_code_codex_and_cursor_get_a_sandbox_in_that_order() {
    let hosts: Vec<Host> = hosts().collect();
    assert_eq!(hosts, [Host::ClaudeCode, Host::Codex, Host::Cursor]);
    assert_eq!(format(Host::OpenClaw), None);
    assert_eq!(format(Host::Continue), None);
    let files: Vec<&str> = hosts
        .iter()
        .filter_map(|h| h.spec().sandbox.as_ref().map(|s| s.file))
        .collect();
    assert_eq!(files, ["settings.json", "config.toml", "sandbox.json"]);
}

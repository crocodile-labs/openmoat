use openmoat_hosts::Host;
use serde_json::json;

use super::*;

fn server(name: &str, entry: Value) -> Server {
    Server {
        id: format!("/h/.claude.json#/mcpServers/{name}"),
        host: Host::EVERY[0],
        file: PathBuf::from("/h/.claude.json"),
        pointer: format!("/mcpServers/{name}"),
        name: name.to_owned(),
        entry,
        form: openmoat_hosts::McpCommandForm::CommandArgs,
    }
}

fn scan(servers: Vec<Server>) -> Scan {
    Scan {
        servers,
        unreadable: Vec::new(),
        scanned: vec![PathBuf::from("/h/.claude.json")],
    }
}

fn pinned(servers: &[Server]) -> Pins {
    servers
        .iter()
        .map(|s| (s.id.clone(), ServerPin::of(s)))
        .collect()
}

#[test]
fn key_order_is_not_a_change() {
    let a = server(
        "gh",
        json!({"command": "npx", "args": ["gh"], "env": {"A": "1", "B": "2"}}),
    );
    let pins = pinned(&[a]);
    let b = server(
        "gh",
        json!({"env": {"B": "2", "A": "1"}, "args": ["gh"], "command": "npx"}),
    );
    assert_eq!(changes(&pins, &scan(vec![b])), Vec::<Change>::new());
}

#[test]
fn a_changed_command_is_named_and_env_values_are_never_shown() {
    let pins = pinned(&[server(
        "gh",
        json!({"command": "npx", "env": {"TOKEN": "secret-one"}}),
    )]);
    let now = server(
        "gh",
        json!({"command": "sh", "env": {"TOKEN": "secret-two", "X": "y"}}),
    );
    let found = changes(&pins, &scan(vec![now]));
    assert_eq!(found.len(), 1);
    let text = found[0].describe();
    assert!(text.contains(r#"command: "npx" → "sh""#), "{text}");
    assert!(
        text.contains("env.TOKEN: changed (value not shown)"),
        "{text}"
    );
    assert!(text.contains("env.X: added (value not shown)"), "{text}");
    assert!(!text.contains("secret"), "{text}");
    let stored = serde_json::to_string(&pins).unwrap();
    assert!(!stored.contains("secret-one"), "{stored}");
    assert!(found[0].blocks());
}

#[test]
fn added_and_removed_servers_are_changes_and_apply_accepts_them() {
    let old = server("old", json!({"command": "a"}));
    let mut pins = pinned(&[old]);
    let new = server("new", json!({"url": "https://mcp.example"}));
    let found = changes(&pins, &scan(vec![new]));
    let kinds: Vec<(&str, &Kind)> = found.iter().map(|c| (c.name.as_str(), &c.kind)).collect();
    assert_eq!(kinds, [("new", &Kind::Added), ("old", &Kind::Removed)]);
    assert!(found[0].blocks() && !found[1].blocks());
    apply(&mut pins, &found);
    assert_eq!(pins.len(), 1);
    assert_eq!(
        changes(
            &pins,
            &scan(vec![server("new", json!({"url": "https://mcp.example"}))])
        ),
        Vec::<Change>::new()
    );
}

#[test]
fn pins_of_files_not_scanned_stay() {
    let pins = pinned(&[server("gh", json!({"command": "a"}))]);
    let elsewhere = Scan {
        scanned: vec![PathBuf::from("/p/.mcp.json")],
        ..Scan::default()
    };
    assert_eq!(changes(&pins, &elsewhere), Vec::<Change>::new());
}

#[test]
fn a_redacted_token_change_still_counts() {
    let pins = pinned(&[server(
        "gh",
        json!({"args": ["--token", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}),
    )]);
    let now = server(
        "gh",
        json!({"args": ["--token", "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}),
    );
    let found = changes(&pins, &scan(vec![now]));
    assert_eq!(found.len(), 1);
    assert!(
        !found[0].describe().contains("ghp_b"),
        "{}",
        found[0].describe()
    );
}

/// A host whose user-level reader names `form`, found by its spec.
fn reading(form: McpCommandForm) -> Host {
    Host::ALL
        .into_iter()
        .find(|h| {
            h.spec()
                .mcp
                .as_ref()
                .is_some_and(|m| m.user_reader.command_form() == form)
        })
        .unwrap()
}

/// `server` read by `host` in its own form.
fn read_by(host: Host, name: &str, entry: Value) -> Server {
    let mut found = server(name, entry);
    found.host = host;
    found.form = host.spec().mcp.as_ref().unwrap().user_reader.command_form();
    found
}

/// The variables each form gives its server: `env`, OpenCode's
/// `environment`, goose's `envs`. A secret there is never stored in the
/// lock's copy and never shown, new or changed.
#[test]
fn a_secret_under_each_form_s_variables_is_never_stored_or_shown() {
    let secret = "first-secret-value";
    for (form, base) in [
        (McpCommandForm::CommandArgs, json!({"command": "npx"})),
        (
            McpCommandForm::CommandList,
            json!({"type": "local", "command": ["npx"]}),
        ),
        (
            McpCommandForm::CmdArgs,
            json!({"type": "stdio", "cmd": "npx"}),
        ),
    ] {
        let host = reading(form);
        let key = read_by(host, "gh", json!({})).form.env_key();
        let mut entry = base;
        entry[key] = json!({"API_KEY": secret});
        let added = changes(
            &Pins::new(),
            &scan(vec![read_by(host, "gh", entry.clone())]),
        );
        let said = added[0].describe();
        assert!(!said.contains(secret), "{key}: {said}");
        let mut pins = Pins::new();
        apply(&mut pins, &added);
        let stored = serde_json::to_string(&pins).unwrap();
        assert!(!stored.contains(secret), "{key}: {stored}");

        entry[key] = json!({"API_KEY": "second-secret-value"});
        let found = changes(&pins, &scan(vec![read_by(host, "gh", entry)]));
        let said = found[0].describe();
        assert!(
            said.contains(&format!("{key}.API_KEY: changed (value not shown)")),
            "{said}"
        );
        assert!(!said.contains("secret-value"), "{key}: {said}");
    }
}

/// An older version kept OpenCode's and goose's values in clear in the
/// copy it shows. The pin still trusts exactly what it trusted, so the
/// same definition needs no new acceptance; a planted change is still
/// held and shows no value; and every save writes the copy without them.
#[test]
fn a_value_an_older_lock_kept_in_clear_is_never_shown_and_saved_away() {
    for (form, key, entry) in [
        (
            McpCommandForm::CommandList,
            "environment",
            json!({"type": "local", "command": ["npx"], "environment": {"API_KEY": "kept-secret-value"}}),
        ),
        (
            McpCommandForm::CmdArgs,
            "envs",
            json!({"type": "stdio", "cmd": "npx", "envs": {"API_KEY": "kept-secret-value"}}),
        ),
    ] {
        let host = reading(form);
        let now = read_by(host, "db", entry.clone());
        let mut old = ServerPin::of(&now);
        old.shown = entry.clone();
        let mut pins = Pins::from([(now.id.clone(), old.clone())]);
        assert_eq!(clear_values(&pins), 1, "{key}");
        assert_eq!(
            changes(&pins, &scan(vec![now])),
            Vec::<Change>::new(),
            "{key}: nothing to accept again"
        );

        let mut planted = entry.clone();
        planted[key]["NODE_OPTIONS"] = json!("--require planted-secret-value");
        let found = changes(&pins, &scan(vec![read_by(host, "db", planted)]));
        assert!(found[0].blocks(), "{key}");
        let said = found[0].describe();
        assert!(
            said.contains(&format!("{key}.NODE_OPTIONS: added")),
            "{said}"
        );
        assert!(!said.contains("secret-value"), "{key}: {said}");
        assert!(!said.contains("API_KEY"), "unchanged, so not named: {said}");

        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("policy.yaml");
        std::fs::write(&policy, "version: 1\n").unwrap();
        let path = dir.path().join("policy.lock");
        let mut lock =
            crate::integrity::Lock::pin(std::path::Path::new("/x/openmoat"), &[policy]).unwrap();
        lock.mcp_servers = Some(pins.clone());
        lock.save(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("kept-secret-value"), "{key}: {text}");
        let saved = crate::integrity::Lock::load(&path)
            .unwrap()
            .mcp_servers
            .unwrap();
        assert_eq!(
            saved[&old_id(&pins)].digest,
            old.digest,
            "trusts what it did"
        );
        assert_eq!(clear_values(&saved), 0);
        assert_eq!(scrub(&mut pins), 1);
        assert_eq!(pins, saved);
    }
}

fn old_id(pins: &Pins) -> String {
    pins.keys().next().unwrap().clone()
}

/// What `openmoat mcp accept` shows before it asks is where a person
/// decides to trust: an escape sequence or a hidden character in a name, a
/// key or an argument never reaches the screen, new or changed.
#[test]
fn what_a_person_is_asked_to_accept_holds_no_escape_sequence() {
    let name = "gh\u{1b}]8;;https://evil\u{7}";
    let entry = json!({"command": "npx", "args": ["\u{202e}lmth.exe", "\u{1b}[2J"]});
    let added = changes(&Pins::new(), &scan(vec![server(name, entry)]));
    let mut pins = Pins::new();
    apply(&mut pins, &added);
    let changed = json!({"command": "sh", "args": ["\u{202e}x", "\u{1b}[31m"],
        "k\u{1b}[1m": 1});
    let found = changes(&pins, &scan(vec![server(name, changed)]));
    for said in [added[0].describe(), found[0].describe()] {
        for bad in ['\u{1b}', '\u{7}', '\u{202e}'] {
            assert!(!said.contains(bad), "{bad:?} in {said:?}");
        }
        assert!(
            said.contains("MCP server `gh?]8;;https://evil?`"),
            "{said:?}"
        );
    }
}

#[test]
fn tool_names_match_their_server_only() {
    assert!(tool_of("mcp__github__get_issue", "github"));
    assert!(!tool_of("mcp__github__get_issue", "git"));
    assert!(tool_of("mcp__my_server__run", "my.server"));
    assert!(!tool_of("mcp__other__run", "my.server"));
}

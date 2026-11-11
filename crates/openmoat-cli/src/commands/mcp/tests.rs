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
    let shown = wrap_servers(&home, binary, &hosts, &names, Some(false), true, &mut out)
        .unwrap()
        .total();
    assert_eq!(shown, 1);
    assert_eq!(fs::read_to_string(&file).unwrap(), text, "a dry run");

    let done = wrap_servers(&home, binary, &hosts, &names, Some(false), false, &mut out)
        .unwrap()
        .total();
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

    assert_eq!(
        unwrap_servers(&home, &hosts, &[], &mut out)
            .unwrap()
            .total(),
        1
    );
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
    let edits = wrap_plan(&home, binary, &hosts, &[], Some(false), &mut out)
        .unwrap()
        .edits;
    assert_eq!(edits.len(), 1, "the stdio extension, not the inline Python");
    let previews = wrap::preview(&edits).unwrap();
    let said = previews[0].change.as_ref().unwrap_err();
    assert!(said.contains("is YAML"), "{said}");
    assert!(said.contains("gh: cmd: \"/x/openmoat\""), "{said}");
    let named = wrap_servers(&home, binary, &hosts, &[], Some(false), false, &mut out).unwrap();
    assert_eq!(
        (named.done, named.by_hand, named.left),
        (0, 1, 1),
        "the stdio extension named to set by hand, the inline Python named and left"
    );
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
    .unwrap()
    .total();
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

#[test]
fn a_server_asked_for_by_name_and_left_to_set_by_hand_is_not_a_success() {
    let names = ["docs".to_owned()];
    let left = Applied {
        done: 0,
        by_hand: 1,
        left: 0,
    };
    assert_eq!(left.code(&names), Code::Usage);
    assert_eq!(left.code(&[]), Code::Ok);
    let done = Applied {
        done: 1,
        by_hand: 0,
        left: 0,
    };
    assert_eq!(done.code(&names), Code::Ok);
}

/// A server's name comes from the agent's file: every line `mcp wrap` prints
/// about it (wrapped, without the sandbox, tools held) shows it through
/// `render::clean`, never with its escape sequences.
#[test]
fn every_line_naming_a_server_is_printed_without_its_escape_sequences() {
    let text = r#"{"mcpServers": {"gh\u001b[2J": {"command": "npx"}}}"#;
    let (_dir, home, _file) = host_with_file(Host::ClaudeCode, ".claude.json", text);
    let mut out = Deferred::capturing();
    let applied = wrap_servers(
        &home,
        Path::new("/x/openmoat"),
        &[Host::ClaudeCode],
        &[],
        Some(false),
        false,
        &mut out,
    )
    .unwrap();
    assert_eq!(applied.total(), 1);
    let said = out.captured();
    assert!(!said.contains('\u{1b}'), "{said:?}");
    for line in [
        "✔ wrapped `gh?[2J`",
        "! `gh?[2J` run without",
        "the tools of `gh?[2J`",
    ] {
        assert!(said.contains(line), "{line}: {said:?}");
    }
}

/// A name asked for that is no server (a typo), or a remote server, is named
/// and is not a success; a named server already wrapped is.
#[test]
fn a_named_server_not_done_is_not_a_success_and_one_already_wrapped_is() {
    let text = r#"{"mcpServers": {"gh": {"command": "npx"},
        "web": {"type": "http", "url": "https://example.invalid"}}}"#;
    let (_dir, home, _file) = host_with_file(Host::ClaudeCode, ".claude.json", text);
    let binary = Path::new("/x/openmoat");
    let hosts = [Host::ClaudeCode];
    let names = |n: &[&str]| n.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let wrap = |asked: &[String]| {
        let mut out = Deferred::capturing();
        let applied =
            wrap_servers(&home, binary, &hosts, asked, Some(false), false, &mut out).unwrap();
        (applied.code(asked), out.captured())
    };

    let typo = names(&["g\u{1b}[2Jh"]);
    let (code, said) = wrap(&typo);
    assert_eq!(code, Code::Usage, "{said}");
    assert!(said.contains("`g?[2Jh` is no MCP server"), "{said:?}");
    let (code, said) = wrap(&names(&["web"]));
    assert_eq!(code, Code::Usage, "{said}");
    assert!(
        said.contains("`web`") && said.contains("nothing to wrap"),
        "{said}"
    );

    let gh = names(&["gh"]);
    assert_eq!(wrap(&gh).0, Code::Ok, "wrapped now");
    let (code, said) = wrap(&gh);
    assert_eq!(code, Code::Ok, "already wrapped: {said}");
    assert!(!said.contains("left as it is"), "{said}");

    let mut out = Deferred::capturing();
    let applied = unwrap_servers(&home, &hosts, &typo, &mut out).unwrap();
    assert_eq!(applied.code(&typo), Code::Usage);
    assert!(
        out.captured().contains("nothing to unwrap"),
        "{}",
        out.captured()
    );
}

/// A server asked for by name that OpenMoat cannot put behind the proxy is
/// named, counted and not a success; a sweep goes on past it.
#[test]
fn a_server_asked_for_by_name_that_cannot_be_wrapped_is_not_a_success() {
    let text = "extensions:\n  snake:\n    enabled: true\n    type: inline_python\n    \
                name: snake\n    code: print(1)\n";
    let (_dir, home, file) = host_with_file(Host::Goose, "config.yaml", text);
    let mut out = Deferred::quiet();
    let binary = Path::new("/x/openmoat");
    let hosts = [Host::Goose];
    let names = ["snake".to_owned()];
    let applied =
        wrap_servers(&home, binary, &hosts, &names, Some(false), false, &mut out).unwrap();
    assert_eq!(applied.total(), 1, "named, so not `no stdio MCP server`");
    assert_eq!(applied.code(&names), Code::Usage);
    let swept = wrap_servers(&home, binary, &hosts, &[], Some(false), false, &mut out).unwrap();
    assert_eq!(swept.code(&[]), Code::Ok);
    assert_eq!(fs::read_to_string(&file).unwrap(), text);
}

/// Only a file OpenMoat deliberately does not rewrite is left to set by hand:
/// a file that no longer holds the server, no longer parses or is gone fails
/// the command, as it did before such files were named.
#[test]
fn a_file_that_changed_under_the_plan_fails_the_command() {
    let text = r#"{"mcpServers": {"gh": {"command": "npx"}}}"#;
    let (_dir, home, file) = host_with_file(Host::ClaudeCode, ".claude.json", text);
    let binary = Path::new("/x/openmoat");
    let hosts = [Host::ClaudeCode];
    let mut out = Deferred::quiet();
    let plan = wrap_plan(&home, binary, &hosts, &[], Some(false), &mut out)
        .unwrap()
        .edits;
    assert_eq!(plan.len(), 1);
    for (now, what) in [
        (Some(r#"{"mcpServers": {}}"#), "no server"),
        (Some("{not json"), "parsing"),
        (None, "reading"),
    ] {
        match now {
            Some(now) => fs::write(&file, now).unwrap(),
            None => fs::remove_file(&file).unwrap(),
        }
        let mut edits = plan.clone();
        let failed = drop_what_cannot_be_rewritten(&mut edits, &mut out).unwrap_err();
        assert!(format!("{failed:#}").contains(what), "{what}: {failed:#}");
    }
}

use std::path::Path;

use openmoat_hosts::McpCommandForm::{CmdArgs, CommandArgs, CommandList};
use serde_json::json;

use super::super::{
    proxy_args, sandboxed, starts_process, unwrapped, with_host, with_sandbox, wrapped_as,
};
use super::*;

const BIN: &str = "/b/openmoat";

#[test]
fn an_opencode_definition_is_wrapped_as_one_list_and_unwrapped_exactly() {
    let entry = json!({"type": "local", "command": ["npx", "-y", "--", "pkg"],
        "environment": {"A": "1"}, "enabled": true});
    let on = wrapped_as(&entry, Path::new(BIN), "db", false, CommandList).unwrap();
    assert_eq!(
        on,
        json!({"type": "local", "environment": {"A": "1"}, "enabled": true,
            "command": [BIN, "mcp", "proxy", "--server", "db", "--", "npx", "-y", "--", "pkg"]})
    );
    assert_eq!(on.get("args"), None, "OpenCode's form has no `args`");
    assert_eq!(unwrapped(&on, CommandList).unwrap(), entry);
    assert_eq!(sandboxed(&on, CommandList), Some(false));
    assert!(
        wrapped_as(&on, Path::new(BIN), "db", false, CommandList).is_none(),
        "wrapped already"
    );
    let named = with_host(&on, CommandList, openmoat_hosts::Host::OpenCode).unwrap();
    assert_eq!(named["command"][0], BIN);
    assert_eq!(named["command"][5], "--host");
    assert_eq!(unwrapped(&named, CommandList).unwrap(), entry);
    let boxed = with_sandbox(&named, CommandList, true).unwrap();
    assert_eq!(sandboxed(&boxed, CommandList), Some(true));
    assert_eq!(unwrapped(&boxed, CommandList).unwrap(), entry);
    assert_eq!(
        proxy_args(&on, CommandList).unwrap()[0..2],
        ["mcp", "proxy"]
    );
}

#[test]
fn a_goose_definition_keeps_cmd_and_args() {
    let entry = json!({"type": "stdio", "name": "GitHub", "cmd": "npx", "args": ["-y", "pkg"],
        "envs": {"A": "1"}, "timeout": 300});
    let on = wrapped_as(&entry, Path::new(BIN), "gh", true, CmdArgs).unwrap();
    assert_eq!(on["cmd"], BIN);
    assert_eq!(on.get("command"), None, "goose reads `cmd`");
    assert_eq!(on["envs"], json!({"A": "1"}));
    assert_eq!(
        on["args"],
        json!([
            "mcp",
            "proxy",
            "--server",
            "gh",
            "--sandbox",
            "--",
            "npx",
            "-y",
            "pkg"
        ])
    );
    assert_eq!(unwrapped(&on, CmdArgs).unwrap(), entry);
}

/// What a host does not run is never read as what it does.
#[test]
fn a_definition_in_another_form_is_not_rewritten() {
    let bin = Path::new(BIN);
    for entry in [
        // OpenCode takes no string `command`, and needs `type: local`.
        json!({"type": "local", "command": "sh"}),
        json!({"command": ["sh", "-c", "x"]}),
        json!({"type": "local", "command": []}),
        json!({"type": "local", "command": ["sh", 1]}),
        // A `cmd` beside the `command` is not OpenCode's.
        json!({"type": "local", "command": ["sh"], "cmd": "other"}),
    ] {
        assert_eq!(
            wrapped_as(&entry, bin, "x", false, CommandList),
            None,
            "{entry}"
        );
        assert!(not_wrappable(&entry, CommandList).is_some(), "{entry}");
    }
    for entry in [
        // goose runs `cmd`: a `command` beside it must not be taken for it.
        json!({"type": "stdio", "cmd": "evil", "command": "harmless"}),
        json!({"type": "stdio", "cmd": "x", "args": [1]}),
        json!({"type": "stdio", "cmd": ["x"]}),
        json!({"cmd": "x"}),
    ] {
        assert_eq!(
            wrapped_as(&entry, bin, "x", false, CmdArgs),
            None,
            "{entry}"
        );
    }
    assert_eq!(
        wrapped_as(&json!({"command": ["x"]}), bin, "x", false, CommandArgs),
        None
    );
}

#[test]
fn a_server_it_cannot_put_behind_the_proxy_is_named_and_a_remote_one_is_not() {
    let python = json!({"type": "inline_python", "code": "print(1)"});
    assert!(not_wrappable(&python, CmdArgs).is_some_and(|why| why.contains("inline Python")));
    let bad = json!({"type": "stdio", "cmd": "x", "args": [1]});
    assert!(not_wrappable(&bad, CmdArgs).is_some());
    for benign in [
        json!({"type": "sse", "uri": "https://x"}),
        json!({"type": "builtin", "name": "developer"}),
    ] {
        assert_eq!(not_wrappable(&benign, CmdArgs), None, "{benign}");
    }
    let remote = json!({"type": "remote", "url": "https://x"});
    assert_eq!(not_wrappable(&remote, CommandList), None);
    // OpenCode entries with nothing to wrap are not warned about.
    for nothing in [
        json!({"enabled": false}),
        json!({"url": "https://x"}),
        json!({"type": "local"}),
    ] {
        assert_eq!(not_wrappable(&nothing, CommandList), None, "{nothing}");
    }
    let ours = json!({"command": ["x"]});
    assert_eq!(not_wrappable(&ours, CommandArgs), None, "as before");
}

#[test]
fn what_starts_a_process_is_read_in_every_form() {
    assert!(starts_process(&json!({"type": "stdio", "cmd": "npx"})));
    assert!(starts_process(
        &json!({"type": "inline_python", "code": "print(1)"})
    ));
    assert!(!starts_process(&json!({"type": "sse", "uri": "https://x"})));
    assert!(!starts_process(&json!({"type": "builtin", "name": "x"})));
    assert!(!starts_process(&json!({"type": "stdio", "cmd": ""})));
    // Both keys: a goose entry that hides its `cmd` still starts something.
    assert!(starts_process(
        &json!({"type": "stdio", "cmd": "evil", "command": "x"})
    ));
}

/// goose runs `cmd` and OpenCode a `cmd` beside its list is not its own: an
/// entry with both keys is never read as wrapped there.
#[test]
fn an_entry_with_both_keys_is_not_wrapped_where_the_host_reads_cmd() {
    let both = json!({"type": "stdio", "cmd": "evil", "command": "/b/openmoat",
        "args": ["mcp", "proxy", "--server", "x", "--", "ok"]});
    let listed = json!({"type": "local", "cmd": "evil",
        "command": ["/b/openmoat", "mcp", "proxy", "--server", "x", "--", "ok"]});
    for (entry, form) in [(&both, CmdArgs), (&listed, CommandList)] {
        assert_eq!(sandboxed(entry, form), None, "{entry}");
        assert_eq!(proxy_args(entry, form), None, "{entry}");
        assert_eq!(unwrapped(entry, form), None, "{entry}");
        assert_eq!(parts(entry, form), None, "{entry}");
    }
}

/// A host whose reader takes `command` and `args` ignores a `cmd` beside
/// them: what wrapping writes there is read back in that form, so it gets its
/// `--host`, and unwrapping restores it.
#[test]
fn a_stray_cmd_does_not_hide_a_wrap_from_a_host_that_reads_command() {
    let entry = json!({"command": "npx", "args": ["pkg"], "cmd": "unused"});
    let on = wrapped_as(&entry, Path::new(BIN), "gh", false, CommandArgs).unwrap();
    assert_eq!(on["cmd"], "unused", "left as it was");
    assert_eq!(sandboxed(&on, CommandArgs), Some(false));
    let named = with_host(&on, CommandArgs, openmoat_hosts::Host::ClaudeCode).unwrap();
    assert!(
        proxy_args(&named, CommandArgs)
            .unwrap()
            .contains(&"--host".to_owned())
    );
    assert_eq!(unwrapped(&named, CommandArgs).unwrap(), entry);
    assert!(with_sandbox(&named, CommandArgs, true).is_some());
}

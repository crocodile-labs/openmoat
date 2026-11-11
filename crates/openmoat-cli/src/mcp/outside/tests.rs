use openmoat_hosts::AutoStart;

use super::*;

fn reader() -> &'static dyn McpAutoStart {
    "claude-code"
        .parse::<Host>()
        .unwrap()
        .spec()
        .mcp
        .as_ref()
        .unwrap()
        .auto_start
        .unwrap()
}

#[test]
fn a_named_or_every_server_starts_unless_turned_off() {
    let mut started = Started::default();
    started.add(
        "/p/.claude/settings.local.json",
        vec![AutoStart::Named {
            key: "enabledMcpjsonServers",
            name: "db".to_owned(),
        }],
    );
    assert!(started.by("db").unwrap().contains("settings.local.json"));
    assert_eq!(started.by("web"), None);
    let root = serde_json::json!({"enableAllProjectMcpServers": true,
        "disabledMcpjsonServers": ["web"]});
    started.add(
        "/u/settings.json",
        reader().settings(root.as_object().unwrap()),
    );
    assert!(
        started
            .by("other")
            .unwrap()
            .contains("enableAllProjectMcpServers")
    );
    assert_eq!(started.by("web"), None, "turned off wins");
    assert!(started.by("db").unwrap().contains("enabledMcpjsonServers"));
}

#[test]
fn each_kind_says_what_to_do() {
    let row = |kind| Outside {
        host: "claude-code".parse().unwrap(),
        name: "gh".to_owned(),
        file: PathBuf::from("/h/.claude.json"),
        kind,
    };
    assert!(
        row(Kind::Unwrapped { user: true })
            .describe()
            .contains("openmoat mcp wrap gh")
    );
    assert!(
        row(Kind::Unwrapped { user: false })
            .describe()
            .contains("project's server")
    );
    assert!(
        row(Kind::Unsandboxed)
            .describe()
            .contains("without the sandbox")
    );
    let by = row(Kind::AutoStarted {
        by: "`x` in f".to_owned(),
    })
    .describe();
    assert!(by.contains("without asking (`x` in f)"), "{by}");
}

/// goose's inline Python cannot be wrapped: the warning does not tell the
/// person to run a command that would leave it as it is.
#[test]
fn inline_python_is_not_told_to_wrap() {
    let python = serde_json::json!({"type": "inline_python", "code": "print(1)"});
    let kind = unwrapped_kind(&python, McpCommandForm::CmdArgs, true);
    assert!(matches!(kind, Kind::CannotWrap { .. }), "{kind:?}");
    let said = Outside {
        host: "goose".parse().unwrap(),
        name: "snake".to_owned(),
        file: PathBuf::from("/h/config.yaml"),
        kind,
    }
    .describe();
    assert!(!said.contains("openmoat mcp wrap snake"), "{said}");
    assert!(
        said.contains("inline Python") && said.contains("remove it"),
        "{said}"
    );
    let stdio = serde_json::json!({"type": "stdio", "cmd": "npx"});
    assert_eq!(
        unwrapped_kind(&stdio, McpCommandForm::CmdArgs, true),
        Kind::Unwrapped { user: true }
    );
    assert_eq!(
        unwrapped_kind(&python, McpCommandForm::CmdArgs, false),
        Kind::Unwrapped { user: false },
        "a project's server keeps its own advice"
    );
}

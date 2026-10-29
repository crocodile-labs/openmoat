use super::{Action, McpCall, UnknownToolCall};

fn parse(json: &str) -> Result<Action, serde_json::Error> {
    serde_json::from_str(json)
}

#[test]
fn json_shape_is_tagged_by_type() {
    assert_eq!(
        serde_json::to_string(&Action::shell("git status")).unwrap(),
        r#"{"type":"shell","command":"git status"}"#
    );
    assert_eq!(
        parse(r#"{"type":"fs_read","path":"/p/a"}"#).unwrap(),
        Action::read("/p/a")
    );
    let mcp = Action::mcp(McpCall::new("mcp__fs__read").reads(["/p/a"]));
    let text = serde_json::to_string(&mcp).unwrap();
    assert_eq!(
        text,
        r#"{"type":"mcp_tool","name":"mcp__fs__read","reads":["/p/a"]}"#
    );
    assert_eq!(parse(&text).unwrap(), mcp);
    let wrapped = Action::unchecked(Action::shell("ls"), "stdin not shown");
    let text = serde_json::to_string(&wrapped).unwrap();
    assert_eq!(parse(&text).unwrap(), wrapped);
}

/// A misspelt or unknown key is an error, never a call with that part missing.
#[test]
fn unknown_fields_and_types_are_errors() {
    for json in [
        r#"{"type":"shell","comand":"rm -rf /"}"#,
        r#"{"type":"shell","command":"ls","cwd":"/"}"#,
        r#"{"type":"mcp_tool","name":"mcp__a__b","read":["/x"]}"#,
        r#"{"type":"unknown_tool","host":"h","tool":"t","args":{}}"#,
        r#"{"type":"exec","command":"ls"}"#,
        r#"{"command":"ls"}"#,
        r#"{"type":"shell"}"#,
    ] {
        assert!(parse(json).is_err(), "{json}");
    }
}

#[test]
fn every_variant_maps_to_the_engine_action_it_names() {
    use openmoat_core::Action as Core;
    let tool = UnknownToolCall::new("me", "deploy")
        .reads(["/r"])
        .writes(["/w"])
        .hosts(["h.example"])
        .commands(["make"]);
    assert_eq!(
        Action::UnknownTool(tool).to_core(),
        Core::UnknownTool {
            host: "me".into(),
            tool: "deploy".into(),
            reads: vec!["/r".into()],
            writes: vec!["/w".into()],
            hosts: vec!["h.example".into()],
            commands: vec!["make".into()],
        }
    );
    let call = McpCall::new("mcp__a__b")
        .writes(["/w"])
        .hosts(["x"])
        .commands(["ls"])
        .opens(["https://docs.example/page"])
        .unchecked("depth");
    assert_eq!(
        Action::mcp(call).to_core(),
        Core::McpTool {
            name: "mcp__a__b".into(),
            reads: Vec::new(),
            writes: vec!["/w".into()],
            hosts: vec!["x".into()],
            commands: vec!["ls".into()],
            opens: vec!["https://docs.example/page".into()],
            unchecked: Some("depth".into()),
        }
    );
    assert_eq!(
        Action::unchecked(Action::net("h"), "why").to_core(),
        Core::unchecked(Core::Net { url: "h".into() }, "why")
    );
    assert_eq!(
        Action::fetch("https://x").to_core(),
        Core::Fetch {
            url: "https://x".into()
        }
    );
    assert_eq!(
        Action::write("/w").to_core(),
        Core::FsWrite { path: "/w".into() }
    );
}

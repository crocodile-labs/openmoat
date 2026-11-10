use super::*;

/// The readers the hosts' specs name, by the layout each reads (hosts by
/// id: only host modules name a host).
mod layout {
    use openmoat_hosts::{Host, McpReader};

    fn mcp(id: &str) -> &'static openmoat_hosts::McpSpec {
        id.parse::<Host>().unwrap().spec().mcp.as_ref().unwrap()
    }
    pub fn json() -> &'static dyn McpReader {
        mcp("cursor").user_reader
    }
    pub fn claude_json() -> &'static dyn McpReader {
        mcp("claude-code").user_reader
    }
    pub fn toml() -> &'static dyn McpReader {
        mcp("codex").user_reader
    }
    pub fn openclaw() -> &'static dyn McpReader {
        mcp("openclaw").user_reader
    }
    pub fn json_or_bare() -> &'static dyn McpReader {
        mcp("copilot-cli").project_files[0].1
    }
}

fn source(reader: &'static dyn McpReader) -> Source {
    Source {
        host: Host::ClaudeCode,
        path: PathBuf::from("/h/.claude.json"),
        reader,
        user: true,
    }
}

#[test]
fn claude_json_lists_user_and_project_servers() {
    let text = r#"{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh"]}},
        "projects": {"/p/a": {"mcpServers": {"db/x": {"command": "db"}}}, "/p/b": {}},
        "numStartups": 4}"#;
    let servers = parse(&source(layout::claude_json()), text).unwrap();
    let ids: Vec<&str> = servers.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "/h/.claude.json#/mcpServers/gh",
            "/h/.claude.json#/projects/~1p~1a/mcpServers/db~1x"
        ]
    );
    assert_eq!(servers[1].name, "db/x");
    assert_eq!(servers[0].entry["args"][1], "gh");
}

#[test]
fn a_plain_json_file_has_no_project_servers() {
    let text = r#"{"mcpServers": {"a": {"url": "https://x"}}, "projects": {"/p": {"mcpServers": {"b": {}}}}}"#;
    let servers = parse(&source(layout::json()), text).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(
        parse(&source(layout::json()), "  ").unwrap(),
        Vec::<Server>::new()
    );
    assert!(parse(&source(layout::json()), "{").is_err());
}

#[test]
fn codex_toml_servers_read_as_json() {
    let text = "model = \"x\"\n[mcp_servers.docs]\ncommand = \"docs-server\"\nargs = [\"--port\", \"4000\"]\nenv = { TOKEN = \"t\" }\nstartup_timeout_sec = 20\n";
    let servers = parse(&source(layout::toml()), text).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].pointer, "/mcp_servers/docs");
    assert_eq!(
        servers[0].entry,
        serde_json::json!({"command": "docs-server", "args": ["--port", "4000"],
            "env": {"TOKEN": "t"}, "startup_timeout_sec": 20})
    );
}

#[test]
fn openclaw_servers_are_read_from_json5() {
    let openclaw = Source {
        host: Host::OpenClaw,
        path: PathBuf::from("/h/.openclaw/openclaw.json"),
        ..source(layout::openclaw())
    };
    let text = "// mine\n{ mcp: { servers: { 'my/docs': { url: 'https://x/mcp', \
                transport: 'streamable-http', }, }, }, gateway: { port: 1 } }";
    let servers = parse(&openclaw, text).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(
        servers[0].id,
        "/h/.openclaw/openclaw.json#/mcp/servers/my~1docs"
    );
    assert_eq!(servers[0].name, "my/docs");
    assert_eq!(servers[0].entry["transport"], "streamable-http");
    assert_eq!(parse(&openclaw, "").unwrap(), Vec::<Server>::new());
    assert_eq!(
        parse(&openclaw, "{ gateway: {} }").unwrap(),
        Vec::<Server>::new()
    );
    for include in [
        r#"{"$include": "./more.json5"}"#,
        r#"{"mcp": {"servers": {"$include": ["./a.json5"]}}}"#,
    ] {
        let refused = parse(&openclaw, include).unwrap_err().to_string();
        assert!(refused.contains("$include"), "{refused}");
    }
    // An `$include` elsewhere cannot bring servers.
    assert!(parse(&openclaw, r#"{"agents": {"$include": "./a.json5"}}"#).is_ok());
}

#[test]
fn copilot_project_files_are_read_wrapped_or_bare() {
    let copilot = Source {
        path: PathBuf::from("/p/.mcp.json"),
        ..source(layout::json_or_bare())
    };
    let wrapped = r#"{"mcpServers": {"gh": {"type": "local", "command": "npx"}}}"#;
    let bare = r#"{"gh": {"type": "local", "command": "npx"}, "web": {"url": "https://x"},
        "note": "not a server", "empty": {}}"#;
    let ids = |text| -> Vec<String> {
        parse(&copilot, text)
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect()
    };
    assert_eq!(ids(wrapped), ["/p/.mcp.json#/mcpServers/gh"]);
    assert_eq!(ids(bare), ["/p/.mcp.json#/gh", "/p/.mcp.json#/web"]);
    assert_eq!(parse(&copilot, "").unwrap(), Vec::<Server>::new());
    assert!(parse(&copilot, "[").is_err());
}

#[test]
fn scan_skips_missing_files_and_reports_broken_ones() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("mcp.json");
    fs::write(&broken, "{not json").unwrap();
    let missing = dir.path().join("absent.json");
    let sources: Vec<Source> = [&broken, &missing]
        .into_iter()
        .map(|p| Source {
            path: p.clone(),
            ..source(layout::json())
        })
        .collect();
    let found = scan(&sources);
    assert_eq!(found.servers, Vec::<Server>::new());
    assert_eq!(found.scanned.len(), 2);
    assert_eq!(found.unreadable.len(), 1);
    assert_eq!(found.unreadable[0].0, broken);
}

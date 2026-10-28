use openmoat_hosts::Host;

use super::names_tool;

#[test]
fn a_hook_decision_names_the_tool_it_decided_and_no_other() {
    let claude = Host::ClaudeCode;
    assert!(names_tool(claude, "mcp__gh__get_issue", "gh", "get_issue"));
    // Claude Code spells a server's and a tool's name with `_` for what it
    // does not keep.
    assert!(names_tool(
        claude,
        "mcp__my_server__get_issue",
        "my.server",
        "get_issue"
    ));
    assert!(names_tool(claude, "mcp__gh__get_issue", "gh", "get.issue"));
    // Another tool of the server, or the same tool of another server: no.
    assert!(!names_tool(claude, "mcp__gh__delete_issue", "gh", "issue"));
    assert!(!names_tool(
        claude,
        "mcp__gh__get_issue",
        "gh",
        "delete_issue"
    ));
    assert!(!names_tool(claude, "mcp__gh__get_issue", "gl", "get_issue"));
    assert!(!names_tool(claude, "mcp__gh__get_issue", "gh", ""));
    // GitHub Copilot CLI joins them with `-`.
    let copilot = Host::CopilotCli;
    assert!(names_tool(copilot, "gh-get_issue", "gh", "get_issue"));
    assert!(!names_tool(copilot, "gh-get_issue", "gh", "issue"));
    // Hermes Agent shortens a name past 64 characters to a hash: no decision
    // names such a tool, so its calls are refused.
    let long = "x".repeat(60);
    let cut = format!("{}_{}", &format!("mcp__gh__{long}")[..55], "0123abcd");
    assert!(!names_tool(Host::Hermes, &cut, "gh", &long));
}

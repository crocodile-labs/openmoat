//! Claude Code's `settings.json` keys that turn OpenMoat's hook off, run a
//! program or redirect the agent (`disableAllHooks`, `hooks`, `env`, helper
//! commands, plugins, sandbox), which GitHub Copilot CLI reads too.
//!
//! OpenMoat pins only the user settings file, which holds its hooks. Claude
//! Code merges the project and local files over it, and a key set there wins:
//! `"disableAllHooks": true` in a project file turns OpenMoat's hooks off with
//! every other hook, and a project's own `hooks`, `env` or command helpers run
//! programs or redirect the agent.

use serde_json::{Map, Value};

use crate::contract::{SettingsFile, SettingsReader, set};

/// Claude Code's reader, also GitHub Copilot CLI's.
#[derive(Debug)]
pub(crate) struct Reader;

pub(crate) static READER: Reader = Reader;

impl SettingsReader for Reader {
    fn findings(&self, file: &SettingsFile<'_>) -> Vec<String> {
        findings(file.root)
    }

    fn switched_off(&self, file: &SettingsFile<'_>) -> Vec<String> {
        findings(file.root)
            .into_iter()
            .filter(|found| found.starts_with("`disableAllHooks`"))
            .collect()
    }
}

/// Keys that name a command Claude Code runs, each with what it is for.
const COMMAND_KEYS: [(&str, &str); 7] = [
    ("apiKeyHelper", "the command that makes the API key"),
    (
        "awsAuthRefresh",
        "the command that refreshes AWS credentials",
    ),
    (
        "awsCredentialExport",
        "the command that exports AWS credentials",
    ),
    (
        "otelHeadersHelper",
        "the command that makes telemetry headers",
    ),
    ("statusLine", "a status line command"),
    ("subagentStatusLine", "a subagent status line command"),
    ("fileSuggestion", "a file suggestion command"),
];

/// What a project settings file sets that could switch OpenMoat off, run a
/// program or redirect the agent; empty when it sets none of that.
///
/// Permission lists and modes are left out on purpose: they decide only
/// whether Claude Code asks the person itself about a call the hook left to
/// it, and Claude Code runs the `PreToolUse` hook in every mode, so OpenMoat's
/// deny and ask stand whatever a project allows. The tool calls of MCP servers
/// a project adds are held by their own pins (ADR-026), but Claude Code starts
/// a server it is told to enable when settings load, which runs its command,
/// so turning project servers on is named.
#[must_use]
pub fn findings(root: &Map<String, Value>) -> Vec<String> {
    let mut found = Vec::new();
    if root
        .get("disableAllHooks")
        .is_some_and(|v| v != &Value::Bool(false))
    {
        found.push("`disableAllHooks` turns off every hook, OpenMoat's included".to_owned());
    }
    if set(root.get("hooks")) {
        found.push("`hooks` adds hooks that run commands".to_owned());
    }
    if set(root.get("env")) {
        found.push(
            "`env` sets environment variables for the session (an API endpoint, a key, a proxy)"
                .to_owned(),
        );
    }
    for (key, what) in COMMAND_KEYS {
        if set(root.get(key)) {
            found.push(format!("`{key}` sets {what}"));
        }
    }
    if root
        .get("enabledPlugins")
        .and_then(Value::as_object)
        .is_some_and(|plugins| plugins.values().any(|v| v != &Value::Bool(false)))
    {
        found.push("`enabledPlugins` turns on plugins, which can carry hooks".to_owned());
    }
    if set(root.get("extraKnownMarketplaces")) {
        found.push(
            "`extraKnownMarketplaces` adds plugin marketplaces, whose plugins can carry hooks"
                .to_owned(),
        );
    }
    for key in ["enableAllProjectMcpServers", "enabledMcpjsonServers"] {
        if set(root.get(key)) {
            found.push(format!(
                "`{key}` starts MCP servers the project's `.mcp.json` names, which runs their \
                 commands (OpenMoat still holds back their tool calls)"
            ));
        }
    }
    if root.get("sandbox").is_some_and(|v| !only_enables(v)) {
        found.push("`sandbox` changes Claude Code's sandbox settings".to_owned());
    }
    found
}

/// `{"enabled": true}` (or nothing at all): a project may turn the sandbox on,
/// never widen or turn off what it allows.
fn only_enables(sandbox: &Value) -> bool {
    match sandbox {
        Value::Null => true,
        Value::Object(o) => o
            .iter()
            .all(|(k, v)| k == "enabled" && v == &Value::Bool(true)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn found(value: &Value) -> Vec<String> {
        findings(value.as_object().unwrap())
    }

    #[test]
    fn names_each_key_that_turns_hooks_off_or_runs_a_program() {
        let all = found(&json!({
            "disableAllHooks": true, "hooks": {"Stop": []}, "env": {"A": "b"},
            "apiKeyHelper": "k", "awsAuthRefresh": "r", "awsCredentialExport": "e",
            "otelHeadersHelper": "h", "statusLine": {"command": "s"},
            "subagentStatusLine": {"command": "s"}, "fileSuggestion": {"command": "f"},
            "enabledPlugins": {"p@m": true}, "sandbox": {"enabled": false},
            "extraKnownMarketplaces": {"m": {"source": {"source": "github", "repo": "o/r"}}},
            "enableAllProjectMcpServers": true, "enabledMcpjsonServers": ["db"],
        }));
        assert_eq!(all.len(), 15, "{all:?}");
        assert!(all[0].contains("OpenMoat's included"), "{all:?}");
        assert!(
            all.iter()
                .any(|f| f.contains("`enabledMcpjsonServers` starts MCP servers")),
            "{all:?}"
        );
    }

    #[test]
    fn leaves_permissions_and_empty_or_switched_off_values_alone() {
        assert!(
            found(&json!({
                "permissions": {"allow": ["Bash"], "defaultMode": "acceptEdits"},
                "disableAllHooks": false, "hooks": {}, "env": {}, "apiKeyHelper": "",
                "statusLine": null, "enabledPlugins": {"p@m": false},
                "sandbox": {"enabled": true}, "model": "opus",
                "enableAllProjectMcpServers": false, "enabledMcpjsonServers": [],
                "extraKnownMarketplaces": {}, "disabledMcpjsonServers": ["db"],
            }))
            .is_empty()
        );
    }
}

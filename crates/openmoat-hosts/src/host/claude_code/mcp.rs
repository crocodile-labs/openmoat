//! Claude Code's `~/.claude.json`: `mcpServers` for the user and
//! `projects.<path>.mcpServers` for each project's local servers; and the
//! settings that start a project's `.mcp.json` servers without asking.

use serde_json::{Map, Value};

use crate::contract::{
    AutoStart, McpAutoStart, McpReader, McpServer, McpServersJson, McpSyntax, escape, servers_at,
};

#[derive(Debug)]
pub(crate) struct ClaudeJson;

impl McpReader for ClaudeJson {
    fn syntax(&self) -> McpSyntax {
        McpSyntax::Json
    }

    fn servers(&self, doc: &Value) -> Result<Vec<McpServer>, String> {
        let mut out = McpServersJson.servers(doc)?;
        if let Some(projects) = doc.get("projects").and_then(Value::as_object) {
            for (project, settings) in projects {
                let at = format!("/projects/{}/mcpServers", escape(project));
                out.extend(servers_at(settings, "mcpServers", &at));
            }
        }
        Ok(out)
    }
}

/// Claude Code asks before it starts a server a project's `.mcp.json`
/// defines, unless a settings file (the person's, the project's shared or
/// local one) or the project's entry in `~/.claude.json` sets
/// `enableAllProjectMcpServers` or names the server in
/// `enabledMcpjsonServers`; `disabledMcpjsonServers` keeps one off. The
/// person's answer to that question is stored the same way.
#[derive(Debug)]
pub(crate) struct AutoStartSettings;

/// Every server of the project starts.
const ALL: &str = "enableAllProjectMcpServers";
/// These servers start.
const ENABLED: &str = "enabledMcpjsonServers";
/// These servers never start.
const DISABLED: &str = "disabledMcpjsonServers";

impl McpAutoStart for AutoStartSettings {
    fn settings(&self, root: &Map<String, Value>) -> Vec<AutoStart> {
        let mut out = Vec::new();
        if root.get(ALL) == Some(&Value::Bool(true)) {
            out.push(AutoStart::All { key: ALL });
        }
        out.extend(
            names(root, ENABLED).map(|name| AutoStart::Named { key: ENABLED, name }),
        );
        out.extend(names(root, DISABLED).map(|name| AutoStart::Off { key: DISABLED, name }));
        out
    }

    fn project_entry<'a>(&self, doc: &'a Value, dir: &str) -> Option<&'a Map<String, Value>> {
        doc.get("projects")?.get(dir)?.as_object()
    }
}

/// The strings in the list at `key` of `root`.
fn names<'a>(root: &'a Map<String, Value>, key: &str) -> impl Iterator<Item = String> + 'a {
    root.get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn auto_start_settings_are_read_from_a_settings_file_and_a_project_entry() {
        let root = json!({"enableAllProjectMcpServers": true,
            "enabledMcpjsonServers": ["db", 3], "disabledMcpjsonServers": ["web"]});
        assert_eq!(
            AutoStartSettings.settings(root.as_object().unwrap()),
            [
                AutoStart::All { key: ALL },
                AutoStart::Named { key: ENABLED, name: "db".to_owned() },
                AutoStart::Off { key: DISABLED, name: "web".to_owned() },
            ]
        );
        let off = json!({"enableAllProjectMcpServers": false});
        assert_eq!(AutoStartSettings.settings(off.as_object().unwrap()), Vec::<AutoStart>::new());
        let doc = json!({"projects": {"/p": {"enabledMcpjsonServers": ["db"]}}});
        assert!(AutoStartSettings.project_entry(&doc, "/p").is_some());
        assert!(AutoStartSettings.project_entry(&doc, "/q").is_none());
    }
}

//! What wrapping would do to a host's files, written nowhere: `moat init`
//! shows it before it asks (ADR-076).

use std::collections::BTreeMap;
use std::path::PathBuf;

use openmoat_hosts::McpSyntax;

use super::{Done, Source, rendered};

/// One file `edits` would change, or why OpenMoat would not rewrite it.
#[derive(Debug)]
pub struct Preview {
    pub path: PathBuf,
    /// The text now and after, or what a person must set by hand instead.
    pub change: Result<(String, String), String>,
}

/// What [`super::write`] would do to each file `edits` touch, writing nothing.
pub fn preview(edits: &[(Source, Done)]) -> Vec<Preview> {
    let mut by_file: BTreeMap<PathBuf, (McpSyntax, Vec<&Done>)> = BTreeMap::new();
    for (source, done) in edits {
        by_file
            .entry(source.path.clone())
            .or_insert_with(|| (source.reader.syntax(), Vec::new()))
            .1
            .push(done);
    }
    by_file
        .into_iter()
        .map(|(path, (syntax, dones))| Preview {
            change: rendered(&path, syntax, &dones).map_err(|e| format!("{e:#}")),
            path,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use openmoat_hosts::Host;
    use serde_json::json;

    use super::super::wrapped;
    use super::*;
    use crate::mcp::servers::Server;

    /// A host whose user-level MCP file has `syntax`, found by its spec.
    fn host_with(syntax: McpSyntax) -> Host {
        Host::ALL
            .into_iter()
            .find(|h| {
                h.spec()
                    .mcp
                    .as_ref()
                    .is_some_and(|m| m.user_reader.syntax() == syntax)
            })
            .unwrap()
    }

    /// Nothing here writes: a preview leaves the file as it was, and names a
    /// file it will not rewrite with what to set by hand.
    #[test]
    fn a_preview_shows_the_change_and_names_a_file_it_will_not_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let source = |syntax: McpSyntax, name: &str, text: &str| {
            let path = dir.path().join(name);
            fs::write(&path, text).unwrap();
            let host = host_with(syntax);
            Source {
                host,
                path,
                reader: host.spec().mcp.as_ref().unwrap().user_reader,
                user: true,
            }
        };
        let done = |source: &Source, pointer: &str| Done {
            server: Server {
                id: String::new(),
                host: source.host,
                file: source.path.clone(),
                pointer: pointer.to_owned(),
                name: "docs".to_owned(),
                entry: json!({}),
            },
            entry: wrapped(
                &json!({"command": "docs"}),
                Path::new("/b/moat"),
                "docs",
                false,
            )
            .unwrap(),
        };
        let text = r#"{"mcpServers": {"docs": {"command": "docs"}}}"#;
        let json_file = source(McpSyntax::Json, "mcp.json", text);
        let yaml_file = source(McpSyntax::Yaml, "config.yaml", "mcp_servers: {}\n");
        let edits = vec![
            (json_file.clone(), done(&json_file, "/mcpServers/docs")),
            (yaml_file.clone(), done(&yaml_file, "/mcp_servers/docs")),
        ];
        let previews = preview(&edits);
        let shown = |path: &Path| previews.iter().find(|p| p.path == path).unwrap();
        let (before, after) = shown(&json_file.path).change.as_ref().unwrap();
        assert_eq!(before, text);
        assert!(after.contains("\"/b/moat\""), "{after}");
        let why = shown(&yaml_file.path).change.as_ref().unwrap_err();
        assert!(why.contains("is YAML") && why.contains("/b/moat"), "{why}");
        assert_eq!(fs::read_to_string(&json_file.path).unwrap(), text);
    }
}

//! MCP server definitions pinned in the policy lock, and how the current ones
//! differ from the pins.
//!
//! A definition is pinned by the SHA-256 of its entry in canonical JSON (keys
//! sorted at every level), not by its file: `~/.claude.json` changes all the
//! time, its servers rarely. The pin also keeps a copy to show a person what
//! changed, with the values of `env` and header maps replaced by digests and
//! token-shaped text redacted, so the lock holds no secret a definition names.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::servers::{Scan, Server};
use crate::integrity::sha256_hex;

/// The keys whose values are shown only as digests: environment variables and
/// HTTP headers often hold tokens.
const HIDDEN_MAPS: &[&str] = &["env", "headers", "http_headers"];

/// One pinned server definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPin {
    /// Host id (`claude-code`, `codex`, `cursor`).
    pub host: String,
    /// The server's name, as the host names its tools (`mcp__<name>__<tool>`).
    pub name: String,
    /// The file that defines it.
    pub file: String,
    /// Lowercase hex SHA-256 of the entry in canonical JSON.
    pub digest: String,
    /// What a person is shown of the entry (see the module documentation).
    pub shown: Value,
}

/// Server id (`<file>#<pointer>`) → pin.
pub type Pins = BTreeMap<String, ServerPin>;

impl ServerPin {
    pub fn of(server: &Server) -> Self {
        Self {
            host: server.host.id().to_owned(),
            name: server.name.clone(),
            file: server.file.display().to_string(),
            digest: sha256_hex(canonical(&server.entry).as_bytes()),
            shown: shown(&server.entry),
        }
    }
}

/// How one definition differs from its pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Not pinned: added since the pins were taken.
    Added,
    /// Pinned with other contents; the lines say what differs.
    Changed(Vec<String>),
    /// Pinned, and its file no longer defines it.
    Removed,
}

/// One server whose definition is not the pinned one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub id: String,
    pub name: String,
    pub host: String,
    pub file: PathBuf,
    pub kind: Kind,
    /// The pin accepting the change stores; `None` drops the pin.
    pub accept: Option<ServerPin>,
}

impl Change {
    /// Whether it should hold back the server's tool calls: a removed server
    /// runs nothing.
    pub fn blocks(&self) -> bool {
        !matches!(self.kind, Kind::Removed)
    }

    /// One line naming the change, then its details indented.
    pub fn describe(&self) -> String {
        let what = match &self.kind {
            Kind::Added => "is new (not pinned yet)",
            Kind::Changed(_) => "changed",
            Kind::Removed => "was removed",
        };
        let mut text = format!(
            "MCP server `{}` in {} {what}",
            self.name,
            self.file.display()
        );
        match &self.kind {
            Kind::Changed(lines) => {
                for line in lines {
                    let _ = write!(text, "\n    {line}");
                }
            }
            Kind::Added => {
                if let Some(pin) = &self.accept {
                    let _ = write!(text, "\n    {}", compact(&pin.shown));
                }
            }
            Kind::Removed => {}
        }
        text
    }
}

/// How the definitions `scan` found differ from `pins`. Pins of files the scan
/// did not look at stay as they are.
pub fn changes(pins: &Pins, scan: &Scan) -> Vec<Change> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for server in &scan.servers {
        seen.insert(server.id.clone());
        let now = ServerPin::of(server);
        let kind = match pins.get(&server.id) {
            None => Kind::Added,
            Some(old) if old.digest == now.digest => continue,
            Some(old) => Kind::Changed(differences(&old.shown, &now.shown)),
        };
        out.push(Change {
            id: server.id.clone(),
            name: server.name.clone(),
            host: now.host.clone(),
            file: server.file.clone(),
            kind,
            accept: Some(now),
        });
    }
    let scanned: BTreeSet<String> = scan
        .scanned
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    for (id, pin) in pins {
        if !seen.contains(id) && scanned.contains(&pin.file) {
            out.push(Change {
                id: id.clone(),
                name: pin.name.clone(),
                host: pin.host.clone(),
                file: PathBuf::from(&pin.file),
                kind: Kind::Removed,
                accept: None,
            });
        }
    }
    out
}

/// Store what accepting `changes` means in `pins`.
pub fn apply(pins: &mut Pins, changes: &[Change]) {
    for change in changes {
        match &change.accept {
            Some(pin) => pins.insert(change.id.clone(), pin.clone()),
            None => pins.remove(&change.id),
        };
    }
}

/// Whether `tool`, a host's MCP tool name, is one of server `name`'s:
/// `mcp__<name>__…`, the name as written or as Claude Code spells it in tool
/// names (every character but letters, digits, `_` and `-` as `_`).
pub fn tool_of(tool: &str, name: &str) -> bool {
    let spelled: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    [name, spelled.as_str()]
        .iter()
        .any(|n| tool.starts_with(&format!("mcp__{n}__")))
}

/// `value` as JSON with every object's keys sorted, so the digest does not
/// depend on the order a host writes them in.
pub fn canonical(value: &Value) -> String {
    openmoat_hosts::canonical_json(value)
}

/// The entry as a person is shown it.
fn shown(entry: &Value) -> Value {
    let mut shown = entry.clone();
    if let Value::Object(map) = &mut shown {
        for key in HIDDEN_MAPS {
            if let Some(Value::Object(values)) = map.get_mut(*key) {
                for value in values.values_mut() {
                    let digest =
                        sha256_hex(format!("openmoat-mcp\0{}", canonical(value)).as_bytes());
                    *value = Value::String(format!("sha256:{}", &digest[..16]));
                }
            }
        }
    }
    openmoat_audit::redact_value(shown)
}

/// One line per top-level key whose shown value differs.
fn differences(old: &Value, new: &Value) -> Vec<String> {
    let empty = serde_json::Map::new();
    let (old_map, new_map) = (
        old.as_object().unwrap_or(&empty),
        new.as_object().unwrap_or(&empty),
    );
    let keys: BTreeSet<&String> = old_map.keys().chain(new_map.keys()).collect();
    let mut lines = Vec::new();
    for key in keys {
        let (before, after) = (old_map.get(key), new_map.get(key));
        if before == after {
            continue;
        }
        if HIDDEN_MAPS.contains(&key.as_str()) {
            lines.extend(hidden_differences(key, before, after));
        } else {
            lines.push(format!(
                "{key}: {} → {}",
                shown_or_none(before),
                shown_or_none(after)
            ));
        }
    }
    if lines.is_empty() {
        // Only a value the pin does not show (a redacted token) differs.
        lines.push("a value OpenMoat does not show changed".to_owned());
    }
    lines
}

fn hidden_differences(key: &str, before: Option<&Value>, after: Option<&Value>) -> Vec<String> {
    let empty = serde_json::Map::new();
    let as_map = |v: Option<&Value>| {
        v.and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(|| empty.clone())
    };
    let (before, after) = (as_map(before), as_map(after));
    let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    names
        .into_iter()
        .filter_map(|name| match (before.get(name), after.get(name)) {
            (None, Some(_)) => Some(format!("{key}.{name}: added (value not shown)")),
            (Some(_), None) => Some(format!("{key}.{name}: removed")),
            (Some(a), Some(b)) if a != b => {
                Some(format!("{key}.{name}: changed (value not shown)"))
            }
            _ => None,
        })
        .collect()
}

fn shown_or_none(value: Option<&Value>) -> String {
    value.map_or_else(|| "(none)".to_owned(), compact)
}

/// Compact JSON, cut to a line's length.
fn compact(value: &Value) -> String {
    const MAX: usize = 300;
    let text = canonical(value);
    if text.chars().count() <= MAX {
        return text;
    }
    let cut: String = text.chars().take(MAX).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use openmoat_hosts::Host;
    use serde_json::json;

    use super::*;

    fn server(name: &str, entry: Value) -> Server {
        Server {
            id: format!("/h/.claude.json#/mcpServers/{name}"),
            host: Host::ClaudeCode,
            file: PathBuf::from("/h/.claude.json"),
            pointer: format!("/mcpServers/{name}"),
            name: name.to_owned(),
            entry,
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
        assert!(changes(&pins, &scan(vec![b])).is_empty());
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
        assert!(
            changes(
                &pins,
                &scan(vec![server("new", json!({"url": "https://mcp.example"}))])
            )
            .is_empty()
        );
    }

    #[test]
    fn pins_of_files_not_scanned_stay() {
        let pins = pinned(&[server("gh", json!({"command": "a"}))]);
        let elsewhere = Scan {
            scanned: vec![PathBuf::from("/p/.mcp.json")],
            ..Scan::default()
        };
        assert!(changes(&pins, &elsewhere).is_empty());
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

    #[test]
    fn tool_names_match_their_server_only() {
        assert!(tool_of("mcp__github__get_issue", "github"));
        assert!(!tool_of("mcp__github__get_issue", "git"));
        assert!(tool_of("mcp__my_server__run", "my.server"));
        assert!(!tool_of("mcp__other__run", "my.server"));
    }
}

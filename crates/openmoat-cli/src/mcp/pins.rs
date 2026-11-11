//! MCP server definitions pinned in the policy lock, and how the current ones
//! differ from the pins.
//!
//! A definition is pinned by the SHA-256 of its entry in canonical JSON (keys
//! sorted at every level), not by its file: `~/.claude.json` changes all the
//! time, its servers rarely. The pin also keeps a copy to show a person what
//! changed (`shown`), with token-shaped text redacted and the values of the
//! maps [`hidden_keys`] names replaced by digests, so the lock holds no secret
//! a definition names: the variables the host gives the server, under the key
//! its form reads them from ([`McpCommandForm::env_key`]: `env`, OpenCode's
//! `environment`, goose's `envs`), and HTTP headers.
//!
//! Older versions hid only `env`, so a lock may keep OpenCode's and goose's
//! values in clear in `shown`. What a pin trusts is its `digest`, of the whole
//! entry, which never depended on `shown`: hiding more changes no digest, so
//! no definition is re-trusted unseen and none has to be accepted again. What
//! is left is the clear copy on disk: every save of the lock writes `shown`
//! without it ([`scrub`]), a comparison hashes an old clear value the same way
//! before comparing, so it shows only names and only real changes, and
//! `openmoat doctor` names a lock that still holds one, which `openmoat
//! doctor --accept` rewrites.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use openmoat_hosts::{Host, McpCommandForm};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::servers::{Scan, Server};
use crate::integrity::sha256_hex;

/// The keys whose values are shown only as digests in a definition its host
/// reads in `form`: the variables it gives the server, and HTTP headers, which
/// often hold tokens.
fn hidden_keys(form: McpCommandForm) -> [&'static str; 3] {
    [form.env_key(), "headers", "http_headers"]
}

/// The form `pin`'s host reads its definitions in; `None` for a host this
/// build does not know, whose pin is hidden in every form.
fn form_of_pin(pin: &ServerPin) -> Option<McpCommandForm> {
    let host: Host = pin.host.parse().ok()?;
    Some(host.spec().mcp.as_ref()?.user_reader.command_form())
}

const EVERY_FORM: [McpCommandForm; 3] = [
    McpCommandForm::CommandArgs,
    McpCommandForm::CommandList,
    McpCommandForm::CmdArgs,
];

/// What a hidden value is shown as.
fn mask(value: &Value) -> Value {
    let digest = sha256_hex(format!("openmoat-mcp\0{}", canonical(value)).as_bytes());
    Value::String(format!("sha256:{}", &digest[..16]))
}

/// Whether `value` is already what [`mask`] shows.
fn is_mask(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}

/// Mask every value under `form`'s hidden keys in `shown` that is not masked
/// yet; how many it masked.
fn hide(shown: &mut Value, form: McpCommandForm) -> usize {
    let Value::Object(map) = shown else {
        return 0;
    };
    let mut masked = 0;
    for key in hidden_keys(form) {
        if let Some(Value::Object(values)) = map.get_mut(key) {
            for value in values.values_mut().filter(|v| !is_mask(v)) {
                *value = mask(value);
                masked += 1;
            }
        }
    }
    masked
}

/// Mask what an older version kept in clear in each pin's `shown`; how many
/// values. The digests, what the pins trust, are left as they are.
pub fn scrub(pins: &mut Pins) -> usize {
    pins.values_mut()
        .map(|pin| match form_of_pin(pin) {
            Some(form) => hide(&mut pin.shown, form),
            None => EVERY_FORM.iter().map(|f| hide(&mut pin.shown, *f)).sum(),
        })
        .sum()
}

/// How many values `pins` keep in clear that [`scrub`] would mask.
pub fn clear_values(pins: &Pins) -> usize {
    scrub(&mut pins.clone())
}

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
            shown: shown(&server.entry, server.form),
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

    /// One line naming the change, then its details indented. This is what a
    /// person reads before they decide to trust a definition, and all of it
    /// comes from the agent's file: every line is shown through
    /// [`crate::render::clean`], so no control or hidden character in a name,
    /// a key or an argument reaches the terminal.
    pub fn describe(&self) -> String {
        let what = match &self.kind {
            Kind::Added => "is new (not pinned yet)",
            Kind::Changed(_) => "changed",
            Kind::Removed => "was removed",
        };
        let mut text = format!(
            "MCP server {} in {} {what}",
            crate::render::Named(&self.name),
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
        crate::render::clean_lines(&text)
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
            Some(old) => {
                // A pin an older version wrote may keep a hidden value in
                // clear: hashed the same way, it is compared, never shown.
                let mut before = old.shown.clone();
                hide(&mut before, server.form);
                Kind::Changed(differences(&before, &now.shown, server.form))
            }
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

/// The entry, read in `form`, as a person is shown it.
fn shown(entry: &Value, form: McpCommandForm) -> Value {
    let mut shown = entry.clone();
    hide(&mut shown, form);
    openmoat_audit::redact_value(shown)
}

/// One line per top-level key whose shown value differs.
fn differences(old: &Value, new: &Value, form: McpCommandForm) -> Vec<String> {
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
        if hidden_keys(form).contains(&key.as_str()) {
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
            host: Host::EVERY[0],
            file: PathBuf::from("/h/.claude.json"),
            pointer: format!("/mcpServers/{name}"),
            name: name.to_owned(),
            entry,
            form: openmoat_hosts::McpCommandForm::CommandArgs,
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
        assert_eq!(changes(&pins, &scan(vec![b])), Vec::<Change>::new());
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
        assert_eq!(
            changes(
                &pins,
                &scan(vec![server("new", json!({"url": "https://mcp.example"}))])
            ),
            Vec::<Change>::new()
        );
    }

    #[test]
    fn pins_of_files_not_scanned_stay() {
        let pins = pinned(&[server("gh", json!({"command": "a"}))]);
        let elsewhere = Scan {
            scanned: vec![PathBuf::from("/p/.mcp.json")],
            ..Scan::default()
        };
        assert_eq!(changes(&pins, &elsewhere), Vec::<Change>::new());
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

    /// A host whose user-level reader names `form`, found by its spec.
    fn reading(form: McpCommandForm) -> Host {
        Host::ALL
            .into_iter()
            .find(|h| {
                h.spec()
                    .mcp
                    .as_ref()
                    .is_some_and(|m| m.user_reader.command_form() == form)
            })
            .unwrap()
    }

    /// `server` read by `host` in its own form.
    fn read_by(host: Host, name: &str, entry: Value) -> Server {
        let mut found = server(name, entry);
        found.host = host;
        found.form = host.spec().mcp.as_ref().unwrap().user_reader.command_form();
        found
    }

    /// The variables each form gives its server: `env`, OpenCode's
    /// `environment`, goose's `envs`. A secret there is never stored in the
    /// lock's copy and never shown, new or changed.
    #[test]
    fn a_secret_under_each_form_s_variables_is_never_stored_or_shown() {
        let secret = "first-secret-value";
        for (form, base) in [
            (McpCommandForm::CommandArgs, json!({"command": "npx"})),
            (
                McpCommandForm::CommandList,
                json!({"type": "local", "command": ["npx"]}),
            ),
            (
                McpCommandForm::CmdArgs,
                json!({"type": "stdio", "cmd": "npx"}),
            ),
        ] {
            let host = reading(form);
            let key = read_by(host, "gh", json!({})).form.env_key();
            let mut entry = base;
            entry[key] = json!({"API_KEY": secret});
            let added = changes(
                &Pins::new(),
                &scan(vec![read_by(host, "gh", entry.clone())]),
            );
            let said = added[0].describe();
            assert!(!said.contains(secret), "{key}: {said}");
            let mut pins = Pins::new();
            apply(&mut pins, &added);
            let stored = serde_json::to_string(&pins).unwrap();
            assert!(!stored.contains(secret), "{key}: {stored}");

            entry[key] = json!({"API_KEY": "second-secret-value"});
            let found = changes(&pins, &scan(vec![read_by(host, "gh", entry)]));
            let said = found[0].describe();
            assert!(
                said.contains(&format!("{key}.API_KEY: changed (value not shown)")),
                "{said}"
            );
            assert!(!said.contains("secret-value"), "{key}: {said}");
        }
    }

    /// An older version kept OpenCode's and goose's values in clear in the
    /// copy it shows. The pin still trusts exactly what it trusted, so the
    /// same definition needs no new acceptance; a planted change is still
    /// held and shows no value; and every save writes the copy without them.
    #[test]
    fn a_value_an_older_lock_kept_in_clear_is_never_shown_and_saved_away() {
        for (form, key, entry) in [
            (
                McpCommandForm::CommandList,
                "environment",
                json!({"type": "local", "command": ["npx"], "environment": {"API_KEY": "kept-secret-value"}}),
            ),
            (
                McpCommandForm::CmdArgs,
                "envs",
                json!({"type": "stdio", "cmd": "npx", "envs": {"API_KEY": "kept-secret-value"}}),
            ),
        ] {
            let host = reading(form);
            let now = read_by(host, "db", entry.clone());
            let mut old = ServerPin::of(&now);
            old.shown = entry.clone();
            let mut pins = Pins::from([(now.id.clone(), old.clone())]);
            assert_eq!(clear_values(&pins), 1, "{key}");
            assert_eq!(
                changes(&pins, &scan(vec![now])),
                Vec::<Change>::new(),
                "{key}: nothing to accept again"
            );

            let mut planted = entry.clone();
            planted[key]["NODE_OPTIONS"] = json!("--require planted-secret-value");
            let found = changes(&pins, &scan(vec![read_by(host, "db", planted)]));
            assert!(found[0].blocks(), "{key}");
            let said = found[0].describe();
            assert!(
                said.contains(&format!("{key}.NODE_OPTIONS: added")),
                "{said}"
            );
            assert!(!said.contains("secret-value"), "{key}: {said}");
            assert!(!said.contains("API_KEY"), "unchanged, so not named: {said}");

            let dir = tempfile::tempdir().unwrap();
            let policy = dir.path().join("policy.yaml");
            std::fs::write(&policy, "version: 1\n").unwrap();
            let path = dir.path().join("policy.lock");
            let mut lock =
                crate::integrity::Lock::pin(std::path::Path::new("/x/openmoat"), &[policy])
                    .unwrap();
            lock.mcp_servers = Some(pins.clone());
            lock.save(&path).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(!text.contains("kept-secret-value"), "{key}: {text}");
            let saved = crate::integrity::Lock::load(&path)
                .unwrap()
                .mcp_servers
                .unwrap();
            assert_eq!(
                saved[&old_id(&pins)].digest,
                old.digest,
                "trusts what it did"
            );
            assert_eq!(clear_values(&saved), 0);
            assert_eq!(scrub(&mut pins), 1);
            assert_eq!(pins, saved);
        }
    }

    fn old_id(pins: &Pins) -> String {
        pins.keys().next().unwrap().clone()
    }

    /// What `openmoat mcp accept` shows before it asks is where a person
    /// decides to trust: an escape sequence or a hidden character in a name, a
    /// key or an argument never reaches the screen, new or changed.
    #[test]
    fn what_a_person_is_asked_to_accept_holds_no_escape_sequence() {
        let name = "gh\u{1b}]8;;https://evil\u{7}";
        let entry = json!({"command": "npx", "args": ["\u{202e}lmth.exe", "\u{1b}[2J"]});
        let added = changes(&Pins::new(), &scan(vec![server(name, entry)]));
        let mut pins = Pins::new();
        apply(&mut pins, &added);
        let changed = json!({"command": "sh", "args": ["\u{202e}x", "\u{1b}[31m"],
            "k\u{1b}[1m": 1});
        let found = changes(&pins, &scan(vec![server(name, changed)]));
        for said in [added[0].describe(), found[0].describe()] {
            for bad in ['\u{1b}', '\u{7}', '\u{202e}'] {
                assert!(!said.contains(bad), "{bad:?} in {said:?}");
            }
            assert!(
                said.contains("MCP server `gh?]8;;https://evil?`"),
                "{said:?}"
            );
        }
    }

    #[test]
    fn tool_names_match_their_server_only() {
        assert!(tool_of("mcp__github__get_issue", "github"));
        assert!(!tool_of("mcp__github__get_issue", "git"));
        assert!(tool_of("mcp__my_server__run", "my.server"));
        assert!(!tool_of("mcp__other__run", "my.server"));
    }
}

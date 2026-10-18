//! Derive the files and hosts an MCP call touches from its arguments.
//!
//! Servers are not standardised, so this is key-based: arguments named like a
//! path become `fs.read` (or `fs.write` for write-shaped tools), arguments named
//! like a URL become `net`, down to `MAX_DEPTH` levels. Unknown shapes add nothing
//! and the call is judged by its name alone. Adding resources can only make a
//! verdict stricter, so arguments that cannot be read are an error (the guard
//! fails closed) rather than silently ignored, and arguments nested past
//! `MAX_DEPTH` are reported in `unchecked` so the call is decided at least `ask`.

use openmoat_core::Action;
use serde_json::Value;

use crate::HostError;

const PATH_KEYS: &[&str] = &[
    "path",
    "paths",
    "file",
    "files",
    "file_path",
    "filepath",
    "filename",
    "directory",
    "dir",
    "source",
    "destination",
    "target",
    "root",
    "cwd",
];
const URL_KEYS: &[&str] = &["url", "urls", "uri", "endpoint", "href"];

/// Nesting below this is not searched; arguments are rarely more than two deep.
const MAX_DEPTH: usize = 8;
/// More derived resources than this is refused rather than half-checked.
const MAX_RESOURCES: usize = 1024;

/// Build the action for `mcp__<server>__<tool>` from the host's `tool_input`.
/// Cursor sends the input as a JSON string, Claude Code and Codex as an object.
pub(crate) fn action(name: &str, input: &Value) -> Result<Action, HostError> {
    let parsed;
    let args = match input {
        Value::String(text) => {
            parsed =
                serde_json::from_str::<Value>(text).map_err(|e| HostError::MalformedArguments {
                    tool: name.to_owned(),
                    problem: e.to_string(),
                })?;
            &parsed
        }
        other => other,
    };
    let tool = name
        .rsplit("__")
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    let mut found = Resources {
        // any word of the name: `file_write`, `bulk_delete` and `download_file`
        // write as surely as `write_file`
        writes_by_default: crate::WRITE_VERBS.iter().any(|verb| tool.contains(verb)),
        ..Resources::default()
    };
    found.walk(args, 0);
    if found.count() > MAX_RESOURCES {
        return Err(HostError::MalformedArguments {
            tool: name.to_owned(),
            problem: format!("more than {MAX_RESOURCES} paths and URLs"),
        });
    }
    Ok(Action::McpTool {
        name: name.to_owned(),
        reads: found.reads,
        writes: found.writes,
        hosts: found.hosts,
        unchecked: found.unchecked,
    })
}

#[derive(Default)]
struct Resources {
    writes_by_default: bool,
    reads: Vec<String>,
    writes: Vec<String>,
    hosts: Vec<String>,
    /// Set when nesting stopped the search.
    unchecked: Option<String>,
}

impl Resources {
    fn count(&self) -> usize {
        self.reads.len() + self.writes.len() + self.hosts.len()
    }

    fn walk(&mut self, value: &Value, depth: usize) {
        if self.count() > MAX_RESOURCES {
            return;
        }
        if depth > MAX_DEPTH {
            // Only an object's keys name resources; the strings of a list, nested
            // or not, were already taken by the key that holds it.
            if holds_object(value) {
                self.unchecked
                    .get_or_insert_with(|| format!("nested deeper than {MAX_DEPTH} levels"));
            }
            return;
        }
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    self.key(&snake(key), value);
                    self.walk(value, depth + 1);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.walk(item, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn key(&mut self, key: &str, value: &Value) {
        let ends = |suffixes: &[&str]| suffixes.iter().any(|s| key.ends_with(&format!("_{s}")));
        if URL_KEYS.contains(&key) || ends(&["url", "uri"]) {
            self.hosts.extend(strings(value));
        } else if PATH_KEYS.contains(&key)
            || ends(&["path", "paths", "dir", "directory", "file", "filename"])
        {
            let is_write = self.writes_by_default || matches!(key, "destination" | "target");
            let sink = if is_write {
                &mut self.writes
            } else {
                &mut self.reads
            };
            sink.extend(strings(value));
        }
    }
}

/// `key` in snake case, as the key lists spell it: `sourcePath`, `source-path`
/// and `SOURCE_PATH` are all `source_path`.
fn snake(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    let mut previous_lower = false;
    for c in key.chars() {
        if c == '-' {
            out.push('_');
        } else if c.is_ascii_uppercase() && previous_lower {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c.to_ascii_lowercase());
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
    }
    out
}

/// Whether `value` is an object or a list holding one at any depth.
fn holds_object(value: &Value) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(_) => return true,
            Value::Array(items) => pending.extend(items),
            _ => {}
        }
    }
    false
}

/// Every non-empty string a path or URL argument holds, through lists nested
/// to any depth: `[["~/.ssh/id_rsa"]]` names the key as surely as a flat list.
/// Objects in the list are searched by [`Resources::walk`] instead.
fn strings(value: &Value) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(s) if !s.is_empty() => found.push(s.clone()),
            Value::Array(items) => pending.extend(items.iter().rev()),
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::{MAX_DEPTH, MAX_RESOURCES, action};
    use openmoat_core::Action;
    use serde_json::json;

    fn ok(name: &str, input: &serde_json::Value) -> Action {
        action(name, input).unwrap()
    }

    fn parts(a: Action) -> (Vec<String>, Vec<String>, Vec<String>) {
        match a {
            Action::McpTool {
                reads,
                writes,
                hosts,
                ..
            } => (reads, writes, hosts),
            other => panic!("not an mcp action: {other:?}"),
        }
    }

    /// Keys in camel or kebab case name paths and URLs like their snake form,
    /// and a write verb anywhere in the tool's name makes its paths writes.
    #[test]
    fn camel_case_keys_and_verbs_anywhere_are_read() {
        let input =
            json!({"sourcePath": "/h/key", "output-dir": "/tmp/o", "baseUrl": "https://x.test"});
        let (reads, writes, hosts) = parts(ok("mcp__fs__stat", &input));
        assert_eq!(reads, ["/tmp/o", "/h/key"], "keys in sorted order");
        assert!(writes.is_empty());
        assert_eq!(hosts, ["https://x.test"]);
        let (_, writes, _) = parts(ok("mcp__fs__file_write", &json!({"targetFile": "/h/rc"})));
        assert_eq!(writes, ["/h/rc"]);
        let (_, writes, _) = parts(ok("mcp__web__download_file", &json!({"path": "/p/a"})));
        assert_eq!(writes, ["/p/a"], "a download writes its path");
    }

    fn unchecked(a: &Action) -> Option<&str> {
        match a {
            Action::McpTool { unchecked, .. } => unchecked.as_deref(),
            other => panic!("not an mcp action: {other:?}"),
        }
    }

    /// `leaf` wrapped in `levels` objects, so its keys are searched at that depth.
    fn nested(levels: usize, leaf: serde_json::Value) -> serde_json::Value {
        (0..levels).fold(leaf, |inner, _| json!({ "options": inner }))
    }

    #[test]
    fn filesystem_read_tools_yield_reads() {
        let a = ok(
            "mcp__filesystem__read_file",
            &json!({"path": "~/.aws/credentials"}),
        );
        assert_eq!(
            parts(a),
            (vec!["~/.aws/credentials".into()], vec![], vec![])
        );
        let a = ok(
            "mcp__filesystem__read_multiple_files",
            &json!({"paths": ["/p/a", "/p/b"]}),
        );
        assert_eq!(parts(a).0, ["/p/a", "/p/b"]);
    }

    #[test]
    fn write_shaped_tools_and_destinations_yield_writes() {
        let a = ok(
            "mcp__filesystem__write_file",
            &json!({"path": "~/.zshrc", "content": "x"}),
        );
        assert_eq!(parts(a).1, ["~/.zshrc"]);
        let a = ok(
            "mcp__filesystem__move_file",
            &json!({"source": "/p/a", "destination": "/p/b"}),
        );
        let (_, mut writes, _) = parts(a);
        writes.sort();
        assert_eq!(writes, ["/p/a", "/p/b"]);
    }

    #[test]
    fn url_arguments_yield_hosts_and_cursor_strings_are_parsed() {
        let a = ok("mcp__fetch__fetch", &json!({"url": "https://evil.com/x"}));
        assert_eq!(parts(a).2, ["https://evil.com/x"]);
        let a = ok(
            "mcp__fetch__fetch",
            &json!("{\"url\":\"https://evil.com/x\"}"),
        );
        assert_eq!(parts(a).2, ["https://evil.com/x"]);
    }

    #[test]
    fn unrelated_arguments_add_nothing() {
        let a = ok(
            "mcp__github__get_pull_request",
            &json!({"owner": "x", "repo": "y", "number": 42}),
        );
        assert_eq!(a, Action::mcp("mcp__github__get_pull_request"));
    }

    #[test]
    fn nested_arguments_and_bare_hosts_are_found() {
        let a = ok(
            "mcp__custom__run",
            &json!({"options": {"files": [{"path": "~/.ssh/id_rsa"}]}, "endpoint": "intranet:8080"}),
        );
        let (reads, _, hosts) = parts(a);
        assert_eq!(reads, ["~/.ssh/id_rsa"]);
        assert_eq!(
            hosts,
            ["intranet:8080"],
            "a URL argument without a scheme is still a host"
        );
    }

    #[test]
    fn paths_in_nested_lists_are_found() {
        let a = ok(
            "mcp__custom__list_files",
            &json!({"paths": [["/p/a", ["~/.ssh/id_rsa"]]], "url": [["https://evil.com"]]}),
        );
        let (reads, _, hosts) = parts(a);
        assert_eq!(reads, ["/p/a", "~/.ssh/id_rsa"]);
        assert_eq!(hosts, ["https://evil.com"]);
        let deep = (0..MAX_DEPTH + 2).fold(json!("~/.ssh/id_rsa"), |inner, _| json!([inner]));
        let a = ok("mcp__custom__list_files", &json!({"path": deep}));
        assert_eq!(unchecked(&a), None, "a list under a path key is read whole");
        assert_eq!(parts(a).0, ["~/.ssh/id_rsa"]);
    }

    #[test]
    fn unreadable_arguments_are_errors_not_silence() {
        let err = action("mcp__filesystem__read_file", &json!("{not json")).unwrap_err();
        assert!(
            err.to_string().contains("mcp__filesystem__read_file"),
            "{err}"
        );
    }

    #[test]
    fn arguments_at_the_depth_limit_are_searched() {
        let a = ok(
            "mcp__custom__run",
            &nested(
                MAX_DEPTH,
                json!({"path": "~/.ssh/id_rsa", "paths": ["/p/a"]}),
            ),
        );
        assert_eq!(unchecked(&a), None);
        assert_eq!(parts(a).0, ["~/.ssh/id_rsa", "/p/a"]);
    }

    #[test]
    fn arguments_past_the_depth_limit_are_reported_unchecked() {
        let deep = nested(MAX_DEPTH + 1, json!({"path": "~/.ssh/id_rsa"}));
        let a = ok(
            "mcp__custom__run",
            &json!({"deep": deep, "url": "https://evil.com"}),
        );
        assert_eq!(unchecked(&a), Some("nested deeper than 8 levels"));
        let (reads, _, hosts) = parts(a);
        assert!(reads.is_empty());
        assert_eq!(
            hosts,
            ["https://evil.com"],
            "what was searched still counts"
        );
        let deep = nested(MAX_DEPTH + 1, json!([{"path": "~/.ssh/id_rsa"}]));
        assert!(unchecked(&ok("mcp__custom__run", &deep)).is_some());
        let deep = nested(MAX_DEPTH + 1, json!([[[{"path": "~/.ssh/id_rsa"}]]]));
        assert!(unchecked(&ok("mcp__custom__run", &deep)).is_some());
        let scalars = nested(MAX_DEPTH, json!({"list": [1, "x"], "empty": []}));
        assert_eq!(unchecked(&ok("mcp__custom__run", &scalars)), None);
    }

    #[test]
    fn paths_past_the_resource_limit_are_errors() {
        let many: Vec<String> = (0..=MAX_RESOURCES).map(|i| format!("/p/{i}")).collect();
        let err = action("mcp__fs__read_multiple_files", &json!({"paths": many})).unwrap_err();
        assert!(err.to_string().contains("more than 1024"), "{err}");
        let exactly = &many[..MAX_RESOURCES];
        let a = ok("mcp__fs__read_multiple_files", &json!({"paths": exactly}));
        assert_eq!(parts(a).0.len(), MAX_RESOURCES);
    }
}

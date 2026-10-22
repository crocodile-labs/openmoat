//! Claude Code's `Artifact` and `ArtifactData` tools, which publish local files
//! to a page on claude.ai and save published files to a local directory.
//!
//! `Artifact` uploads its `file_path`, each of `file_paths`, and every source
//! of `files` (a map from the published path to a source path or `{from}`, or
//! a list of `{path}`), a relative source taken from `root` when given; with
//! `action: "read"` it saves `path` or each of `paths` under `out_dir`, and
//! otherwise brings the page into the session like a fetch: a page someone
//! else wrote is untrusted content, so it taints the session as `WebFetch` does.
//! `ArtifactData` reads a local JSON `file_path`. A file sent off the machine
//! is read like `SendFile`'s, so a deny on reading it holds.

use openmoat_core::Action;
use serde_json::Value;

use crate::HostError;

const ARTIFACT: &str = "Artifact";

/// The files `Artifact` reads or writes; `None` for a call that names no
/// local file (`list`, `open`, `delete`, a server-side copy).
pub(super) fn artifact(input: &Value) -> Result<Option<Action>, HostError> {
    let root = optional(input, "root")?;
    if input.get("action").and_then(Value::as_str) == Some("read")
        && optional(input, "out_dir")?.is_none()
        && let Some(url) = optional(input, "url")?
    {
        return Ok(Some(Action::Fetch { url }));
    }
    let mut reads = Vec::new();
    // A relative `file_path` or `file_paths` is read from the working
    // directory, or, for an Artifact made from a type, may be one below `root`:
    // both are read.
    let mut either = |path: String| {
        let below = under(root.as_deref(), &path)?;
        reads.push(path.clone());
        if below != path {
            reads.push(below);
        }
        Ok::<_, HostError>(())
    };
    if let Some(path) = optional(input, "file_path")? {
        either(path)?;
    }
    match input.get("file_paths") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            for path in list {
                either(path_str(path)?)?;
            }
        }
        Some(_) => return Err(malformed("`file_paths` is not a list of paths")),
    }
    match input.get("files") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for source in map.values() {
                match source {
                    Value::Null => {}
                    Value::String(path) => reads.push(under(root.as_deref(), path)?),
                    Value::Object(spec) if spec.contains_key("artifact") => {}
                    Value::Object(spec) => {
                        let from = spec.get("from").ok_or_else(|| malformed("no `from`"))?;
                        reads.push(under(root.as_deref(), &path_str(from)?)?);
                    }
                    _ => return Err(malformed("a `files` source is not a path")),
                }
            }
        }
        Some(Value::Array(list)) => {
            for entry in list {
                let path = entry.get("path").ok_or_else(|| malformed("no `path`"))?;
                reads.push(under(root.as_deref(), &path_str(path)?)?);
            }
        }
        Some(_) => return Err(malformed("`files` is not a map or a list")),
    }
    let writes = saved(input)?;
    Ok(match (reads.len(), writes.is_empty()) {
        (0, true) => None,
        (0, false) => Some(Action::Patch { writes }),
        (_, true) => Some(Action::ReadFiles { paths: reads }),
        (_, false) => return Err(malformed("the call both uploads and saves files")),
    })
}

/// `ArtifactData` reads its `file_path`, a local JSON file, when it names one.
pub(super) fn artifact_data(input: &Value) -> Result<Option<Action>, HostError> {
    Ok(optional(input, "file_path")?.map(|path| Action::FsRead { path }))
}

/// Where `action: "read"` with an `out_dir` saves each published file; its
/// default directory is the session's own scratch directory.
fn saved(input: &Value) -> Result<Vec<String>, HostError> {
    let Some(dir) = optional(input, "out_dir")? else {
        return Ok(Vec::new());
    };
    let mut named = Vec::new();
    named.extend(optional(input, "path")?);
    if let Some(list) = input.get("paths").and_then(Value::as_array) {
        for path in list {
            named.push(path_str(path)?);
        }
    }
    if named.is_empty() {
        return Ok(vec![dir]);
    }
    let dir = dir.trim_end_matches(['/', '\\']);
    Ok(named.iter().map(|path| format!("{dir}/{path}")).collect())
}

/// A relative source below `root`, when the call names one.
fn under(root: Option<&str>, path: &str) -> Result<String, HostError> {
    if path.is_empty() {
        return Err(malformed("a source path is empty"));
    }
    let relative = !(path.starts_with(['/', '\\', '~'])
        || path.as_bytes().get(1) == Some(&b':') && path.as_bytes()[0].is_ascii_alphabetic());
    Ok(match root {
        Some(root) if relative => format!("{}/{path}", root.trim_end_matches(['/', '\\'])),
        _ => path.to_owned(),
    })
}

fn optional(input: &Value, key: &str) -> Result<Option<String>, HostError> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => path_str(value).map(Some),
    }
}

fn path_str(value: &Value) -> Result<String, HostError> {
    value
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| malformed("a path argument is not a non-empty string"))
}

fn malformed(problem: &str) -> HostError {
    HostError::MalformedArguments {
        tool: ARTIFACT.to_owned(),
        problem: problem.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use openmoat_core::Action;
    use serde_json::json;

    use super::{artifact, artifact_data};

    #[test]
    fn every_local_file_an_artifact_publishes_is_read() {
        let input = json!({
            "file_path": "page.html", "root": "/Users/me/.ssh",
            "files": {"k.txt": "id_rsa", "s.css": {"from": "/p/s.css"},
                      "c.js": {"artifact": "https://claude.ai/artifact/x", "path": "c.js"},
                      "old.png": null},
        });
        assert_eq!(
            artifact(&input).unwrap(),
            Some(Action::ReadFiles {
                paths: vec![
                    "page.html".into(),
                    "/Users/me/.ssh/page.html".into(),
                    "/Users/me/.ssh/id_rsa".into(),
                    "/p/s.css".into()
                ]
            })
        );
        let assets = json!({"url": "u", "asset": true, "file_paths": ["~/.aws/credentials"]});
        assert_eq!(
            artifact(&assets).unwrap(),
            Some(Action::ReadFiles {
                paths: vec!["~/.aws/credentials".into()]
            })
        );
        let listed = json!({"files": [{"path": "a.js"}], "file_path": "i.html"});
        assert!(
            matches!(artifact(&listed).unwrap(), Some(Action::ReadFiles { paths }) if paths.len() == 2)
        );
    }

    #[test]
    fn a_read_into_a_directory_writes_there_and_listing_touches_nothing() {
        let input = json!({"action": "read", "url": "u", "path": "a.js", "out_dir": "~/.zshrc.d/"});
        assert_eq!(
            artifact(&input).unwrap(),
            Some(Action::Patch {
                writes: vec!["~/.zshrc.d/a.js".into()]
            })
        );
        assert_eq!(artifact(&json!({"action": "list"})).unwrap(), None);
        // a page read into the session is fetched content
        assert_eq!(
            artifact(&json!({"action": "read", "url": "https://claude.ai/artifact/x"})).unwrap(),
            Some(Action::Fetch {
                url: "https://claude.ai/artifact/x".into()
            })
        );
        assert_eq!(
            artifact(&json!({"action": "read", "type_url": "t"})).unwrap(),
            None
        );
        assert_eq!(
            artifact_data(&json!({"file_path": "/p/rows.json"})).unwrap(),
            Some(Action::FsRead {
                path: "/p/rows.json".into()
            })
        );
    }

    #[test]
    fn arguments_that_cannot_be_read_are_errors() {
        for input in [
            json!({"file_path": 1}),
            json!({"file_paths": "a"}),
            json!({"files": {"a": 1}}),
            json!({"files": {"a": {"contentType": "x"}}}),
            json!({"files": [{"from": "a"}]}),
            json!({"files": "a"}),
            json!({"file_path": "a", "out_dir": "/tmp", "path": "b"}),
        ] {
            assert!(artifact(&input).is_err(), "{input}");
        }
    }
}

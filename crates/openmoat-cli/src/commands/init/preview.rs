//! What `moat init` would change in one agent's files, shown before it asks:
//! a summary per file by default, the full unified diff on request.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use similar::{Algorithm, ChangeTag, TextDiff, udiff::unified_diff};

use crate::home::Home;
use crate::install::HostConfig;
use crate::render::{DIFF_CONTEXT_LINES, Deferred};
use crate::sandbox::{self, Plan};

/// One file `init` would write: its path, its text now and after.
pub(super) struct Change {
    path: PathBuf,
    before: String,
    after: String,
}

/// Every change `init` would make to `config`'s host: its hooks and, with
/// `plan`, its sandbox settings, combined where they share a file (Claude
/// Code's `settings.json`). Writes nothing.
pub(super) fn changes(
    home: &Home,
    config: &HostConfig,
    binary: &Path,
    plan: Option<&Plan>,
) -> Result<Vec<Change>> {
    let path = config.settings_path.clone();
    let before = sandbox::install::read_text(&path)?;
    let after = config
        .render(binary, &before)?
        .unwrap_or_else(|| before.clone());
    let mut changes = vec![Change {
        path,
        before,
        after,
    }];
    // The host's record of consent to the hook (Hermes Agent's allowlist).
    if let Some((path, consent)) = crate::install::consent::of(config) {
        let before = sandbox::install::read_text(&path)?;
        let after = crate::install::consent::render(config, consent, &path, binary, &before)?
            .unwrap_or_else(|| before.clone());
        changes.push(Change {
            path,
            before,
            after,
        });
    }
    let host = config.host;
    if let Some(plan) = plan
        && sandbox::install::format(host).is_some()
    {
        let path = sandbox::install::settings_path(home, host)?;
        if let Some(shared) = changes.iter_mut().find(|c| c.path == path) {
            if let Some(r) = sandbox::install::render(home, host, plan, &shared.after)? {
                shared.after = r.text;
            }
        } else {
            let before = sandbox::install::read_text(&path)?;
            let after = sandbox::install::render(home, host, plan, &before)?
                .map_or_else(|| before.clone(), |r| r.text);
            changes.push(Change {
                path,
                before,
                after,
            });
        }
    }
    changes.retain(|c| c.before != c.after);
    Ok(changes)
}

/// One line per changed file: new or edited, lines added and removed, and the
/// top-level settings it sets when the file is JSON or TOML.
pub(super) fn summary(config: &HostConfig, changes: &[Change], out: &mut Deferred) -> Result<()> {
    if changes.is_empty() {
        writeln!(out, "  no change to {}'s files", config.host.display_name())?;
    }
    for change in changes {
        writeln!(out, "  {}", summary_line(change))?;
    }
    Ok(())
}

/// Print every change as a unified diff.
pub(super) fn diff(changes: &[Change], out: &mut Deferred) -> Result<()> {
    for change in changes {
        let name = change.path.display().to_string();
        let diff = unified_diff(
            Algorithm::Myers,
            &change.before,
            &change.after,
            DIFF_CONTEXT_LINES,
            Some((
                &format!("{name} (now)"),
                &format!("{name} (after openmoat init)"),
            )),
        );
        write!(out, "{diff}")?;
    }
    Ok(())
}

fn summary_line(change: &Change) -> String {
    let (added, removed) = line_counts(&change.before, &change.after);
    let kind = if change.before.trim().is_empty() {
        "new file"
    } else {
        "edited"
    };
    let keys = changed_keys(&change.path, &change.before, &change.after);
    let sets = if keys.is_empty() {
        String::new()
    } else {
        format!("; sets {}", keys.into_iter().collect::<Vec<_>>().join(", "))
    };
    format!(
        "{}: {kind}, +{added} -{removed} lines{sets}",
        change.path.display()
    )
}

fn line_counts(before: &str, after: &str) -> (usize, usize) {
    let diff = TextDiff::from_lines(before, after);
    diff.iter_all_changes()
        .fold((0, 0), |(added, removed), c| match c.tag() {
            ChangeTag::Insert => (added + 1, removed),
            ChangeTag::Delete => (added, removed + 1),
            ChangeTag::Equal => (added, removed),
        })
}

/// The top-level keys whose values differ between `before` and `after`, for a
/// JSON or TOML file that parses both ways; empty for any other file.
fn changed_keys(path: &Path, before: &str, after: &str) -> BTreeSet<String> {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    match extension {
        "json" => json_keys(before, after).unwrap_or_default(),
        "yaml" => yaml_keys(before, after).unwrap_or_default(),
        "toml" => toml_keys(before, after).unwrap_or_default(),
        _ => BTreeSet::new(),
    }
}

/// The top-level keys whose values differ between two YAML texts.
fn yaml_keys(before: &str, after: &str) -> Option<BTreeSet<String>> {
    let parse = |text: &str| match openmoat_hosts::yaml_hooks::parse(text).ok()? {
        serde_json::Value::Object(map) => Some(map),
        _ => None,
    };
    let (before, after) = (parse(before)?, parse(after)?);
    Some(
        before
            .keys()
            .chain(after.keys())
            .filter(|k| before.get(*k) != after.get(*k))
            .cloned()
            .collect(),
    )
}

fn json_keys(before: &str, after: &str) -> Option<BTreeSet<String>> {
    let parse = |text: &str| -> Option<serde_json::Map<String, serde_json::Value>> {
        if text.trim().is_empty() {
            return Some(serde_json::Map::new());
        }
        match serde_json::from_str(text).ok()? {
            serde_json::Value::Object(map) => Some(map),
            _ => None,
        }
    };
    let (before, after) = (parse(before)?, parse(after)?);
    Some(
        before
            .keys()
            .chain(after.keys())
            .filter(|k| before.get(*k) != after.get(*k))
            .cloned()
            .collect(),
    )
}

fn toml_keys(before: &str, after: &str) -> Option<BTreeSet<String>> {
    let parse = |text: &str| text.parse::<toml_edit::DocumentMut>().ok();
    let (before, after) = (parse(before)?, parse(after)?);
    let text = |doc: &toml_edit::DocumentMut, key: &str| doc.get(key).map(ToString::to_string);
    Some(
        before
            .iter()
            .map(|(k, _)| k)
            .chain(after.iter().map(|(k, _)| k))
            .filter(|k| text(&before, k) != text(&after, k))
            .map(str::to_owned)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(path: &str, before: &str, after: &str) -> Change {
        Change {
            path: PathBuf::from(path),
            before: before.to_owned(),
            after: after.to_owned(),
        }
    }

    #[test]
    fn a_new_json_file_names_every_top_level_key() {
        let line = summary_line(&change(
            "/h/.claude/settings.json",
            "",
            "{\n  \"hooks\": {},\n  \"sandbox\": {\"enabled\": true}\n}\n",
        ));
        assert_eq!(
            line,
            "/h/.claude/settings.json: new file, +4 -0 lines; sets hooks, sandbox"
        );
    }

    #[test]
    fn an_edited_json_file_names_only_the_keys_that_change() {
        let line = summary_line(&change(
            "/h/settings.json",
            "{\n  \"theme\": \"dark\",\n  \"hooks\": {}\n}\n",
            "{\n  \"theme\": \"dark\",\n  \"hooks\": {\"PreToolUse\": []}\n}\n",
        ));
        assert_eq!(line, "/h/settings.json: edited, +1 -1 lines; sets hooks");
    }

    #[test]
    fn a_toml_file_names_changed_tables_and_keys() {
        let keys = changed_keys(
            Path::new("config.toml"),
            "model = \"x\"\n",
            "model = \"x\"\n[sandbox_workspace_write]\nnetwork_access = false\n",
        );
        assert_eq!(
            keys.into_iter().collect::<Vec<_>>(),
            ["sandbox_workspace_write"]
        );
    }

    #[test]
    fn other_or_unparsable_files_name_no_keys() {
        assert!(changed_keys(Path::new("openmoat.js"), "", "x").is_empty());
        assert!(changed_keys(Path::new("s.json"), "{", "{}").is_empty());
        assert!(changed_keys(Path::new("s.json"), "[]", "{}").is_empty());
    }
}

//! pi's `settings.json` entries that turn OpenMoat's extension off or load
//! more code (pi 1.3.0 `docs/settings.md`, "Resources";
//! `dist/core/package-manager.js`).
//!
//! An `extensions` entry `!<glob>` excludes the extensions it matches, by their
//! path relative to the settings file's base directory, their file name or
//! their absolute path; `+<path>` puts one back and `-<path>` excludes one
//! exactly, whatever else says (`isEnabledByOverrides`). The user's entries
//! decide for OpenMoat's auto-discovered extension; a trusted project's are
//! resolved first, and the first registration of a path wins, so a project
//! entry that names the extension can turn it off too.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::contract::{SettingsFile, SettingsReader, set};

#[derive(Debug)]
pub(crate) struct Reader;

pub(crate) static READER: Reader = Reader;

impl SettingsReader for Reader {
    fn findings(&self, file: &SettingsFile<'_>) -> Vec<String> {
        findings(file.root, file.base, file.hook_file, file.user_home)
    }

    fn switched_off(&self, file: &SettingsFile<'_>) -> Vec<String> {
        switched_off(file.root, file.base, file.hook_file, file.user_home)
    }

    fn hook_dir_effect(&self) -> &'static str {
        "is an extension pi loads with the agent's rights"
    }
}

/// Whether the user's `settings.json` `root`, whose relative entries resolve
/// from `base` (the agent directory) and `~` from `home`, turns off
/// OpenMoat's extension at `extension`; the entry that does when it does.
fn switched_off(
    root: &Map<String, Value>,
    base: &Path,
    extension: &Path,
    home: Option<&Path>,
) -> Vec<String> {
    let entries = entries(root);
    let excluded = entries
        .iter()
        .filter_map(|e| e.strip_prefix('!'))
        .find(|glob| glob_names(glob, base, extension, home));
    let put_back = entries
        .iter()
        .filter_map(|e| e.strip_prefix('+'))
        .any(|exact| exact_names(exact, base, extension, home));
    let forced = entries
        .iter()
        .filter_map(|e| e.strip_prefix('-'))
        .find(|exact| exact_names(exact, base, extension, home));
    match (forced, excluded, put_back) {
        (Some(entry), _, _) => vec![off(&format!("-{entry}"))],
        (None, Some(entry), false) => vec![off(&format!("!{entry}"))],
        _ => Vec::new(),
    }
}

/// What a trusted project's `.pi/settings.json` `root` (base `base`) sets that
/// may turn OpenMoat's extension at `extension` off or loads code with the
/// agent's rights. Any exclusion that names the extension is named, as the
/// project's entries are resolved before the user's.
fn findings(
    root: &Map<String, Value>,
    base: &Path,
    extension: &Path,
    home: Option<&Path>,
) -> Vec<String> {
    let entries = entries(root);
    let mut found: Vec<String> = entries
        .iter()
        .filter(|e| match (e.strip_prefix('!'), e.strip_prefix('-')) {
            (Some(glob), _) => glob_names(glob, base, extension, home),
            (_, Some(exact)) => exact_names(exact, base, extension, home),
            _ => false,
        })
        .map(|e| off(e))
        .collect();
    if entries
        .iter()
        .any(|e| !e.starts_with(['!', '+', '-']) && !e.starts_with("builtin:"))
    {
        found.push("`extensions` loads extensions, which run with the agent's rights".to_owned());
    }
    if set(root.get("packages")) {
        found.push(
            "`packages` installs pi packages, whose extensions run with the agent's rights"
                .to_owned(),
        );
    }
    found
}

fn off(entry: &str) -> String {
    format!("`extensions` entry `{entry}` turns OpenMoat's extension off")
}

/// The string entries of `extensions`.
fn entries(root: &Map<String, Value>) -> Vec<&str> {
    root.get("extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// `entry` as pi resolves a path: `~` is the home directory, `./` is dropped.
fn resolved(entry: &str, home: Option<&Path>) -> String {
    let entry = entry.strip_prefix("./").unwrap_or(entry);
    match (entry.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => posix(&home.join(rest)),
        _ => entry.replace('\\', "/"),
    }
}

fn posix(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The ways pi names `extension` to a pattern from a file based at `base`.
fn names(base: &Path, extension: &Path) -> Vec<String> {
    let mut out = vec![posix(extension)];
    if let Ok(rel) = extension.strip_prefix(base) {
        out.push(posix(rel));
    }
    if let Some(name) = extension.file_name() {
        out.push(name.to_string_lossy().into_owned());
    }
    out
}

/// A `-` or `+` entry: the path relative to `base`, or absolute.
fn exact_names(entry: &str, base: &Path, extension: &Path, home: Option<&Path>) -> bool {
    let entry = resolved(entry, home);
    let absolute = PathBuf::from(&entry);
    let full = if absolute.is_absolute() {
        absolute
    } else {
        base.join(&entry)
    };
    posix(&full) == posix(extension)
}

/// A `!` entry, a minimatch glob. Syntax beyond `*`, `?` and `**` (braces,
/// classes, negation) is taken as matching: the warning is the safe side.
fn glob_names(glob: &str, base: &Path, extension: &Path, home: Option<&Path>) -> bool {
    let glob = resolved(glob, home);
    if glob.contains(['{', '[', '(', '!', '+', '@']) {
        return true;
    }
    names(base, extension)
        .iter()
        .any(|name| matches(&glob, name))
}

/// Whether `text` matches `glob` segment by segment: `*` and `?` stay within
/// a segment, `**` spans any number of them.
fn matches(glob: &str, text: &str) -> bool {
    let globs: Vec<&str> = glob.split('/').collect();
    let parts: Vec<&str> = text.split('/').collect();
    segments(&globs, &parts)
}

fn segments(globs: &[&str], parts: &[&str]) -> bool {
    match globs.split_first() {
        None => parts.is_empty(),
        Some((&"**", rest)) => (0..=parts.len()).any(|skip| segments(rest, &parts[skip..])),
        Some((first, rest)) => parts.split_first().is_some_and(|(part, others)| {
            segment(first.as_bytes(), part.as_bytes()) && segments(rest, others)
        }),
    }
}

fn segment(glob: &[u8], text: &[u8]) -> bool {
    match glob.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|skip| segment(rest, &text[skip..])),
        Some((b'?', rest)) => !text.is_empty() && segment(rest, &text[1..]),
        Some((c, rest)) => text.first() == Some(c) && segment(rest, &text[1..]),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const BASE: &str = "/h/.pi/agent";
    const EXT: &str = "/h/.pi/agent/extensions/openmoat.js";

    fn off(extensions: &Value) -> Vec<String> {
        let root = json!({ "extensions": extensions });
        switched_off(
            root.as_object().unwrap(),
            Path::new(BASE),
            Path::new(EXT),
            None,
        )
    }

    #[test]
    fn an_entry_that_excludes_the_extension_turns_it_off() {
        for entry in [
            "-extensions/openmoat.js",
            "-./extensions/openmoat.js",
            "-/h/.pi/agent/extensions/openmoat.js",
            "!openmoat.js",
            "!*.js",
            "!extensions/*",
            "!**/openmoat.*",
            "!{openmoat,x}.js",
        ] {
            assert_eq!(off(&json!([entry])).len(), 1, "{entry}");
        }
    }

    #[test]
    fn other_entries_and_a_put_back_leave_it_on() {
        for entries in [
            json!([]),
            json!([
                "-extensions/other.js",
                "!*.ts",
                "!other/*",
                "builtin:mcp",
                "-builtin:mcp"
            ]),
            json!(["!*.js", "+extensions/openmoat.js"]),
            json!("not a list"),
        ] {
            assert!(off(&entries).is_empty(), "{entries}");
        }
        // `-` wins over `+`.
        assert_eq!(
            off(&json!([
                "+extensions/openmoat.js",
                "-extensions/openmoat.js"
            ]))
            .len(),
            1
        );
    }

    #[test]
    fn a_project_that_excludes_it_or_loads_code_is_named() {
        let project = Path::new("/p/.pi");
        let found = |root: Value| findings(root.as_object().unwrap(), project, Path::new(EXT), None);
        assert_eq!(found(json!({"extensions": ["!openmoat.js"]})).len(), 1);
        assert_eq!(
            found(json!({"extensions": ["-/h/.pi/agent/extensions/openmoat.js"]})).len(),
            1
        );
        assert_eq!(
            found(json!({"extensions": ["./tools.ts"], "packages": ["npm:x"]})).len(),
            2
        );
        assert!(found(json!({"extensions": ["-builtin:mcp"], "packages": []})).is_empty());
    }

    #[test]
    fn globs_match_segment_by_segment() {
        assert!(matches("*.js", "openmoat.js"));
        assert!(!matches("*.js", "extensions/openmoat.js"));
        assert!(matches("**/*.js", "extensions/openmoat.js"));
        assert!(matches("ext?nsions/**", "extensions/a/b.js"));
        assert!(!matches("other/**", "extensions/openmoat.js"));
    }
}

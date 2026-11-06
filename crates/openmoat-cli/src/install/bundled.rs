//! The copies of a host's program that editor extensions ship off the search
//! path ([`openmoat_hosts::HostSpec::bundled`]): the Claude Code extension for
//! VS Code and its forks runs its own Claude Code, which reads the same
//! `settings.json` as the CLI.
//!
//! Each editor lists its installed extensions in `extensions.json` in its
//! extensions folder, with each one's version and folder; a folder it has
//! replaced but not yet deleted is not listed. Without that file, every
//! folder named `<extension id>-<version>…` counts, an old one included: a
//! copy too many only makes `moat init` leave out a key it could have
//! written, never write one a copy cannot read. The extension's version is
//! the version of the program it bundles (<https://code.claude.com/docs/en/vs-code>),
//! so nothing is run to learn it.

use std::path::{Path, PathBuf};

use openmoat_hosts::{Bundle, Host};
use serde::Deserialize;

use super::claude_version::{Version, parse};

/// One bundled copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundledCopy {
    /// The editor whose extension ships it.
    pub editor: &'static str,
    /// The extension's folder.
    pub dir: PathBuf,
    /// The extension's version, which is the bundled program's.
    pub version: Version,
}

/// Every copy of `host`'s program its editors' extensions ship in the home
/// folder, newest first within each editor; none when the home folder is
/// unknown.
pub fn copies(host: Host) -> Vec<BundledCopy> {
    let Ok(home) = crate::home::user_home() else {
        return Vec::new();
    };
    host.spec()
        .bundled
        .iter()
        .flat_map(|bundle| in_home(&home, bundle))
        .collect()
}

/// The copies `bundle` names below `home`.
fn in_home(home: &Path, bundle: &Bundle) -> Vec<BundledCopy> {
    let dir = bundle
        .extensions_dir
        .iter()
        .fold(home.to_path_buf(), |dir, part| dir.join(part));
    let mut found = match std::fs::read(dir.join("extensions.json")) {
        Ok(bytes) => listed(&dir, bundle, &bytes),
        Err(_) => scanned(&dir, bundle),
    };
    found.sort_by_key(|copy| std::cmp::Reverse(copy.version));
    found
}

/// One entry of `extensions.json`.
#[derive(Deserialize)]
struct Entry {
    identifier: Identifier,
    version: String,
    #[serde(rename = "relativeLocation")]
    relative_location: Option<String>,
}

#[derive(Deserialize)]
struct Identifier {
    id: String,
}

/// The extension's entries in `extensions.json`, each whose folder is there.
/// A file that cannot be read as the list falls back to the folders.
fn listed(dir: &Path, bundle: &Bundle, bytes: &[u8]) -> Vec<BundledCopy> {
    let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(bytes) else {
        return scanned(dir, bundle);
    };
    entries
        .into_iter()
        .filter_map(|value| serde_json::from_value::<Entry>(value).ok())
        .filter(|e| e.identifier.id.eq_ignore_ascii_case(bundle.extension_id))
        .filter_map(|e| {
            // a folder inside the extensions directory: `extensions.json` is a
            // file in the home, and an absolute path or `..` would point a copy
            // anywhere
            let location = e.relative_location?;
            let inside = Path::new(&location)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)));
            if !inside {
                return None;
            }
            let folder = dir.join(location);
            let version = parse(&e.version)?;
            folder.is_dir().then_some(BundledCopy {
                editor: bundle.editor,
                dir: folder,
                version,
            })
        })
        .collect()
}

/// Every folder named after the extension and a version.
fn scanned(dir: &Path, bundle: &Bundle) -> Vec<BundledCopy> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let prefix = format!("{}-", bundle.extension_id);
    entries
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            let version = parse(name.strip_prefix(&prefix)?)?;
            Some(BundledCopy {
                editor: bundle.editor,
                dir: e.path(),
                version,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: Bundle = Bundle::new(
        "VS Code",
        &[".vscode", "extensions"],
        "anthropic.claude-code",
    );

    fn extensions(home: &Path) -> PathBuf {
        let dir = home.join(".vscode/extensions");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_list_names_the_installed_copies_whose_folders_are_there() {
        let home = tempfile::tempdir().unwrap();
        let dir = extensions(home.path());
        std::fs::create_dir(dir.join("anthropic.claude-code-2.1.318-darwin-arm64")).unwrap();
        // Replaced, not yet deleted, and no longer listed.
        std::fs::create_dir(dir.join("anthropic.claude-code-2.1.200-darwin-arm64")).unwrap();
        let list = serde_json::json!([
            {"identifier": {"id": "Anthropic.claude-code"}, "version": "2.1.318",
             "relativeLocation": "anthropic.claude-code-2.1.318-darwin-arm64"},
            {"identifier": {"id": "anthropic.claude-code"}, "version": "2.1.100",
             "relativeLocation": "anthropic.claude-code-2.1.100-darwin-arm64"},
            {"identifier": {"id": "ms-python.python"}, "version": "2026.1.0",
             "relativeLocation": "ms-python.python-2026.1.0"},
            // a folder outside the extensions directory is no copy, even one that exists
            {"identifier": {"id": "anthropic.claude-code"}, "version": "9.9.9",
             "relativeLocation": "../../outside"},
            {"not": "an entry"}
        ]);
        std::fs::create_dir(home.path().join("outside")).unwrap();
        std::fs::write(dir.join("extensions.json"), list.to_string()).unwrap();
        let found = in_home(home.path(), &BUNDLE);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].version, (2, 1, 318));
        assert!(
            found[0]
                .dir
                .ends_with("anthropic.claude-code-2.1.318-darwin-arm64")
        );
    }

    #[test]
    fn without_a_list_every_folder_counts() {
        let home = tempfile::tempdir().unwrap();
        let dir = extensions(home.path());
        for name in [
            "anthropic.claude-code-2.1.300",
            "anthropic.claude-code-2.1.318-win32-x64",
            "anthropic.claude-code-x",
            "other.claude-code-9.9.9",
        ] {
            std::fs::create_dir(dir.join(name)).unwrap();
        }
        std::fs::write(dir.join("anthropic.claude-code-3.0.0"), "a file").unwrap();
        let found: Vec<Version> = in_home(home.path(), &BUNDLE)
            .into_iter()
            .map(|c| c.version)
            .collect();
        assert_eq!(found, [(2, 1, 318), (2, 1, 300)]);
        std::fs::write(dir.join("extensions.json"), "not json").unwrap();
        assert_eq!(in_home(home.path(), &BUNDLE).len(), 2, "an unreadable list");
    }

    #[test]
    fn no_folder_no_copies() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(in_home(home.path(), &BUNDLE), Vec::new());
    }
}

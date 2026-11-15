//! What the project already provides a package runner (ADR-102): a program
//! in `node_modules/.bin`, or a package its nearest manifest declares. The
//! core asks only for a runner's word that would otherwise need review
//! (`package-run-unknown`), so an ordinary call reads nothing here.
//!
//! Reading fails towards review: a manifest that is missing, too large or
//! does not parse declares nothing.

use std::path::Path;

use openmoat_core::Ecosystem;
use serde_json::Value;
use toml_edit::{DocumentMut, Item};

/// Manifests larger than this are not read.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Whether `name` is a program in `node_modules/.bin` of one of `dirs`.
pub fn local_bin(dirs: &[String], name: &str) -> bool {
    if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
        return false;
    }
    dirs.iter().any(|dir| {
        let bin = Path::new(dir).join("node_modules").join(".bin");
        [name.to_owned(), format!("{name}.cmd")]
            .iter()
            .any(|file| bin.join(file).exists())
    })
}

/// Whether the nearest manifest in `dirs` (searched in order) declares
/// `name`: `package.json`'s `dependencies`, `devDependencies` and
/// `optionalDependencies` for npm; `pyproject.toml`'s dependency lists, or
/// else `uv.lock`'s packages, for the Python Package Index.
pub fn declared(dirs: &[String], ecosystem: Ecosystem, name: &str) -> bool {
    match ecosystem {
        Ecosystem::Npm => {
            nearest(dirs, &["package.json"]).is_some_and(|(_, text)| npm_declares(&text, name))
        }
        Ecosystem::Pypi => {
            let key = ecosystem.normalise(name);
            nearest(dirs, &["pyproject.toml", "uv.lock"]).is_some_and(|(file, text)| {
                let doc = text.parse::<DocumentMut>().ok();
                doc.is_some_and(|doc| match file {
                    "uv.lock" => locked(&doc, ecosystem).contains(&key),
                    _ => required(&doc, ecosystem).contains(&key),
                })
            })
        }
        _ => false,
    }
}

/// The first of `files` found in the first of `dirs` that holds one, and its text.
fn nearest(dirs: &[String], files: &[&'static str]) -> Option<(&'static str, String)> {
    dirs.iter().find_map(|dir| {
        files.iter().find_map(|file| {
            let path = Path::new(dir).join(file);
            let meta = std::fs::metadata(&path).ok()?;
            if !meta.is_file() || meta.len() > MAX_MANIFEST_BYTES {
                return None;
            }
            Some((*file, std::fs::read_to_string(&path).ok()?))
        })
    })
}

fn npm_declares(text: &str, name: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    ["dependencies", "devDependencies", "optionalDependencies"]
        .iter()
        .any(|key| {
            doc.get(key)
                .and_then(Value::as_object)
                .is_some_and(|deps| deps.contains_key(name))
        })
}

/// The names a `pyproject.toml` requires, normalised: `project.dependencies`
/// and `optional-dependencies`, `dependency-groups`, `tool.uv.dev-dependencies`
/// and Poetry's dependency tables.
fn required(doc: &DocumentMut, ecosystem: Ecosystem) -> Vec<String> {
    let mut lists: Vec<&Item> = Vec::new();
    let item = doc.as_item();
    lists.extend(item.get("project").and_then(|p| p.get("dependencies")));
    for table in [
        item.get("project")
            .and_then(|p| p.get("optional-dependencies")),
        item.get("dependency-groups"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(t) = table.as_table_like() {
            lists.extend(t.iter().map(|(_, v)| v));
        }
    }
    lists.extend(
        item.get("tool")
            .and_then(|t| t.get("uv"))
            .and_then(|u| u.get("dev-dependencies")),
    );
    let mut names: Vec<String> = lists
        .into_iter()
        .filter_map(Item::as_array)
        .flat_map(|a| a.iter().filter_map(|v| v.as_str()))
        .filter_map(requirement_name)
        .map(|n| ecosystem.normalise(n))
        .collect();
    // Poetry: tables keyed by the package name
    let poetry = item.get("tool").and_then(|t| t.get("poetry"));
    let mut tables: Vec<&Item> = Vec::new();
    tables.extend(poetry.and_then(|p| p.get("dependencies")));
    tables.extend(poetry.and_then(|p| p.get("dev-dependencies")));
    if let Some(groups) = poetry
        .and_then(|p| p.get("group"))
        .and_then(Item::as_table_like)
    {
        tables.extend(groups.iter().filter_map(|(_, g)| g.get("dependencies")));
    }
    for table in tables.into_iter().filter_map(Item::as_table_like) {
        names.extend(table.iter().map(|(k, _)| ecosystem.normalise(k)));
    }
    names
}

/// The names of `uv.lock`'s `[[package]]` entries, normalised.
fn locked(doc: &DocumentMut, ecosystem: Ecosystem) -> Vec<String> {
    doc.get("package")
        .and_then(Item::as_array_of_tables)
        .map(|packages| {
            packages
                .iter()
                .filter_map(|p| p.get("name").and_then(Item::as_str))
                .map(|n| ecosystem.normalise(n))
                .collect()
        })
        .unwrap_or_default()
}

/// The project name a requirement (`ruff>=0.5`, `uvicorn[standard]`) names.
fn requirement_name(requirement: &str) -> Option<&str> {
    let requirement = requirement.trim();
    let end = requirement
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(requirement.len());
    (end > 0).then(|| &requirement[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(files: &[(&str, &str)]) -> (tempfile::TempDir, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let root = dir.path().to_string_lossy().into_owned();
        let dirs = vec![format!("{root}/app"), root];
        (dir, dirs)
    }

    #[test]
    fn a_program_in_node_modules_bin_up_to_the_project_is_local() {
        let (_dir, dirs) = project(&[("node_modules/.bin/tsc", ""), ("app/x", "")]);
        assert!(local_bin(&dirs, "tsc"));
        assert!(!local_bin(&dirs, "ng"));
        assert!(!local_bin(&dirs, "../.bin/tsc"));
    }

    #[test]
    fn the_nearest_package_json_declares_its_dependencies() {
        let (_dir, dirs) = project(&[
            (
                "package.json",
                r#"{"devDependencies": {"outer-tool": "1"}}"#,
            ),
            (
                "app/package.json",
                r#"{"dependencies": {"@acme/cli": "1"}, "devDependencies": {"drizzle-kit": "0.3"}, "scripts": {"x": "helper"}}"#,
            ),
        ]);
        assert!(declared(&dirs, Ecosystem::Npm, "@acme/cli"));
        assert!(declared(&dirs, Ecosystem::Npm, "drizzle-kit"));
        // only the nearest manifest, and only its dependency lists
        assert!(!declared(&dirs, Ecosystem::Npm, "outer-tool"));
        assert!(!declared(&dirs, Ecosystem::Npm, "helper"));
        assert!(!declared(&dirs, Ecosystem::Pypi, "drizzle-kit"));
    }

    #[test]
    fn pyproject_and_uv_lock_declare_their_projects() {
        let pyproject = "[project]\nname = \"x\"\ndependencies = [\"Requests>=2\"]\n\
            [project.optional-dependencies]\ndev = [\"basedpyright[all]\"]\n\
            [dependency-groups]\nlint = [\"acme_lint==1\"]\n\
            [tool.poetry.group.test.dependencies]\npytest-acme = \"^1\"\n";
        let (_dir, dirs) = project(&[("app/pyproject.toml", pyproject)]);
        for name in ["requests", "basedpyright", "acme-lint", "pytest_acme"] {
            assert!(declared(&dirs, Ecosystem::Pypi, name), "{name}");
        }
        assert!(!declared(&dirs, Ecosystem::Pypi, "x-other"));
        let lock = "version = 1\n[[package]]\nname = \"ty\"\nversion = \"0.1\"\n";
        let (_dir, dirs) = project(&[("uv.lock", lock)]);
        assert!(declared(&dirs, Ecosystem::Pypi, "ty"));
        let (_dir, dirs) = project(&[("app/pyproject.toml", "not = [toml")]);
        assert!(!declared(&dirs, Ecosystem::Pypi, "ty"));
    }
}

//! Package manifests: the dependencies and install scripts a change adds.
//!
//! Only added lines are read, one at a time, so a dependency is recognised by
//! the shape of its line (`"name": "^1.2"`, `name = "1.0"`, `name>=2`,
//! `require mod v1`, `gem "name"`), not by the section it sits in: a line of
//! another section with that shape (`"version": "1.0.0"`) is told apart by
//! its key, and a name is only reported when it is a near miss of a popular
//! one, which ordinary keys are not.

use super::files::Manifest;
use super::{Change, Hit, INSTALL_SCRIPT, Level, PACKAGE_NEAR_MISS, PACKAGE_SOURCE, shown};
use crate::packages::{Ecosystem, near_miss};

/// The npm scripts npm runs on every install of the package (and of the
/// repository itself); `prepare` runs for git dependencies too.
const INSTALL_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

/// `package.json` keys whose value has a dependency's shape but is not one.
const NPM_KEYS: &[&str] = &[
    "name",
    "version",
    "description",
    "main",
    "module",
    "types",
    "typings",
    "license",
    "author",
    "homepage",
    "private",
    "type",
    "packagemanager",
    "repository",
    "bugs",
    "funding",
    "url",
    "node",
    "npm",
    "pnpm",
    "yarn",
    "bun",
    "browser",
    "bin",
    "exports",
    "registry",
    "access",
    "tag",
    "directory",
    "path",
    "files",
    "workspaces",
    "email",
    "web",
];

/// TOML keys of `pyproject.toml` and `Cargo.toml` that are not dependencies.
const TOML_KEYS: &[&str] = &[
    "name",
    "version",
    "edition",
    "authors",
    "license",
    "license-file",
    "description",
    "readme",
    "repository",
    "homepage",
    "documentation",
    "rust-version",
    "resolver",
    "publish",
    "build",
    "python",
    "requires-python",
    "python-versions",
    "requires",
    "build-backend",
    "package",
    "default-run",
    "links",
    "keywords",
    "categories",
    "include",
    "exclude",
    "members",
];

pub(super) fn scan(manifest: Manifest, change: &Change<'_>, hits: &mut Vec<Hit>) {
    for (line, text) in change.added {
        let line = *line;
        match manifest {
            Manifest::Npm => npm(line, text, hits),
            Manifest::Requirements => requirement(line, text, hits),
            Manifest::PyProject => {
                if let Some(spec) = quoted_item(text) {
                    pep508(line, spec, true, hits);
                } else if let Some(items) = dependency_array(text) {
                    for item in items.split(',').filter_map(quoted_item) {
                        pep508(line, item, false, hits);
                    }
                } else {
                    toml_dependency(Ecosystem::Pypi, line, text, hits);
                }
            }
            Manifest::Cargo => toml_dependency(Ecosystem::Crates, line, text, hits),
            Manifest::GoMod => go(line, text, hits),
            Manifest::Gemfile => gem(line, text, hits),
        }
    }
}

fn near(ecosystem: Ecosystem, name: &str, line: usize, hits: &mut Vec<Hit>) {
    if let Some(popular) = near_miss(ecosystem, name) {
        hits.push(Hit::new(
            PACKAGE_NEAR_MISS,
            Level::Review,
            line,
            format!(
                "adds the {} dependency `{}`, one typo or trick away from the popular `{popular}`, \
                 as typo-squats and made-up names are; check which one is meant",
                ecosystem.id(),
                shown(name)
            ),
        ));
    }
}

fn source(name: &str, from: &str, line: usize, hits: &mut Vec<Hit>) {
    hits.push(Hit::new(
        PACKAGE_SOURCE,
        Level::Review,
        line,
        format!(
            "takes the dependency `{}` from {}, outside its registry: whoever controls it can \
             change the code without a new version",
            shown(name),
            shown(from)
        ),
    ));
}

/// Whether a dependency spec is fetched from somewhere other than the registry.
fn remote(spec: &str) -> bool {
    let s = spec.trim().to_ascii_lowercase();
    [
        "git+",
        "git:",
        "git@",
        "github:",
        "gitlab:",
        "bitbucket:",
        "http://",
        "https://",
        "ssh://",
    ]
    .iter()
    .any(|p| s.starts_with(p))
}

/// `"key": "value"` (a trailing comma allowed).
fn json_pair(text: &str) -> Option<(&str, &str)> {
    let t = text.trim().trim_end_matches(',');
    let rest = t.strip_prefix('"')?;
    let (key, rest) = rest.split_once('"')?;
    let value = rest.trim_start().strip_prefix(':')?.trim();
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    Some((key, value))
}

fn npm(line: usize, text: &str, hits: &mut Vec<Hit>) {
    let Some((key, value)) = json_pair(text) else {
        return;
    };
    if INSTALL_SCRIPTS.contains(&key) {
        hits.push(Hit::new(
            INSTALL_SCRIPT,
            Level::Review,
            line,
            format!(
                "sets the `{key}` script, which npm runs on every install, with the rights of \
                 whoever installs: `{}`",
                shown(value)
            ),
        ));
        return;
    }
    let valid_name = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "@/._-".contains(c));
    if !valid_name || NPM_KEYS.contains(&key) {
        return;
    }
    let v = value.trim();
    if remote(v) || owner_repo(v) {
        source(key, v, line, hits);
        near(Ecosystem::Npm, key, line, hits);
        return;
    }
    let versioned = v.starts_with(|c: char| c.is_ascii_digit() || "^~<>=*".contains(c))
        || matches!(v, "latest" | "next" | "x")
        || v.starts_with("npm:")
        || v.starts_with("workspace:");
    if versioned {
        near(Ecosystem::Npm, key, line, hits);
        // `"alias": "npm:real-name@^1"` installs `real-name`
        if let Some(real) = v.strip_prefix("npm:") {
            let real = real
                .rsplit_once('@')
                .filter(|(n, _)| !n.is_empty())
                .map_or(real, |(n, _)| n);
            near(Ecosystem::Npm, real, line, hits);
        }
    }
}

/// `owner/repo` or `owner/repo#ref`: npm reads it as a GitHub repository.
fn owner_repo(spec: &str) -> bool {
    let body = spec.split('#').next().unwrap_or(spec);
    let mut parts = body.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let word = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    };
    word(owner) && word(repo) && !owner.starts_with('.') && !spec.contains(':')
}

/// The leading package name of a requirement (`requests[socks]>=2` → `requests`).
fn requirement_name(spec: &str) -> &str {
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || "._-".contains(c)))
        .unwrap_or(spec.len());
    &spec[..end]
}

fn requirement(line: usize, text: &str, hits: &mut Vec<Hit>) {
    let t = text.split(" #").next().unwrap_or(text).trim();
    if t.is_empty() || t.starts_with('#') {
        return;
    }
    if let Some(rest) = t
        .strip_prefix("-e ")
        .or_else(|| t.strip_prefix("--editable "))
    {
        let rest = rest.trim();
        if remote(rest) {
            source(rest, rest, line, hits);
        }
        return;
    }
    if t.starts_with('-') {
        return;
    }
    if remote(t) {
        let name = t.rsplit_once("#egg=").map_or(t, |(_, n)| n);
        source(name, t, line, hits);
        return;
    }
    pep508(line, t, false, hits);
}

/// A PEP 508 requirement. In `pyproject.toml` (`strict`) a bare quoted word
/// may be a keyword or a classifier, so it needs a version, extras, a marker
/// or a URL to count as a dependency.
fn pep508(line: usize, spec: &str, strict: bool, hits: &mut Vec<Hit>) {
    let name = requirement_name(spec);
    if name.is_empty() {
        return;
    }
    let rest = spec[name.len()..].trim_start();
    if strict && !rest.starts_with(['<', '>', '=', '!', '~', '[', ';', '@']) {
        return;
    }
    if let Some((_, url)) = rest.split_once('@')
        && remote(url.trim())
    {
        source(name, url.trim(), line, hits);
    }
    near(Ecosystem::Pypi, name, line, hits);
}

/// The text of a quoted array item: `"requests>=2",`.
fn quoted_item(text: &str) -> Option<&str> {
    let t = text.trim().trim_end_matches(',').trim();
    t.strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .or_else(|| t.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')))
}

/// The items of `dependencies = ["a>=1", "b"]` (any key naming dependencies, and
/// `requires`), written on one line.
fn dependency_array(text: &str) -> Option<&str> {
    let (key, value) = text.split_once('=')?;
    let key = key.trim().to_ascii_lowercase();
    if !(key.contains("dependencies") || key == "requires") {
        return None;
    }
    value.trim().strip_prefix('[')?.trim_end().strip_suffix(']')
}

/// `name = "1.0"` or `name = { version = "1", git = "…" }`, and `[dependencies.name]`.
fn toml_dependency(ecosystem: Ecosystem, line: usize, text: &str, hits: &mut Vec<Hit>) {
    let t = text.trim();
    if let Some(header) = t.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        if let Some((section, name)) = header.rsplit_once('.')
            && section.ends_with("dependencies")
        {
            near(ecosystem, name.trim_matches('"'), line, hits);
        }
        return;
    }
    let Some((key, value)) = t.split_once('=') else {
        return;
    };
    let key = key.trim().trim_matches('"');
    let value = value.trim();
    let valid_key = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !valid_key || TOML_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
        return;
    }
    if let Some(inner) = value.strip_prefix('{') {
        let keys = [
            "version",
            "git",
            "path",
            "workspace",
            "url",
            "registry",
            "branch",
        ];
        if !keys.iter().any(|k| inner.contains(&format!("{k} ="))) {
            return;
        }
        if let Some(url) = table_value(inner, "git").or_else(|| table_value(inner, "url")) {
            source(key, url, line, hits);
        }
        near(
            ecosystem,
            table_value(inner, "package").unwrap_or(key),
            line,
            hits,
        );
        return;
    }
    let spec = value.trim_matches(['"', '\'']);
    let versioned = value.starts_with(['"', '\''])
        && spec.starts_with(|c: char| c.is_ascii_digit() || "^~<>=*".contains(c));
    if versioned {
        near(ecosystem, key, line, hits);
    }
}

/// The quoted value of `key = "…"` inside an inline table.
fn table_value<'t>(inner: &'t str, key: &str) -> Option<&'t str> {
    let at = inner.find(&format!("{key} ="))?;
    let rest = inner[at + key.len() + 2..].trim_start().strip_prefix('"')?;
    rest.split('"').next()
}

fn go(line: usize, text: &str, hits: &mut Vec<Hit>) {
    let t = text.split("//").next().unwrap_or(text).trim();
    if let Some(rest) = t.strip_prefix("replace ").or_else(|| {
        // inside a `replace (` block: `old => new v1`
        t.contains("=>").then_some(t)
    }) {
        if let Some((old, new)) = rest.split_once("=>") {
            let old = old.split_whitespace().next().unwrap_or_default();
            let new = new.trim();
            source(old, &format!("`{new}` (a replace directive)"), line, hits);
        }
        return;
    }
    let body = t.strip_prefix("require ").unwrap_or(t).trim();
    let mut words = body.split_whitespace();
    if let (Some(module), Some(version)) = (words.next(), words.next())
        && module.contains('.')
        && version.starts_with('v')
    {
        near(Ecosystem::Go, module, line, hits);
    }
}

fn gem(line: usize, text: &str, hits: &mut Vec<Hit>) {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix("source ") {
        let url = rest.trim().trim_matches(['"', '\'']);
        if url.trim_end_matches('/') != "https://rubygems.org" {
            source("(every gem of this Gemfile)", url, line, hits);
        }
        return;
    }
    let Some(rest) = t
        .strip_prefix("gem ")
        .or_else(|| t.strip_prefix("spec.add_dependency "))
        .or_else(|| t.strip_prefix("spec.add_runtime_dependency "))
        .or_else(|| t.strip_prefix("spec.add_development_dependency "))
    else {
        return;
    };
    let rest = rest.trim().trim_start_matches('(');
    let Some(quote @ ('"' | '\'')) = rest.chars().next() else {
        return;
    };
    let Some(name) = rest[1..].split(quote).next() else {
        return;
    };
    for key in ["git:", "github:", ":git =>", ":github =>"] {
        if let Some((_, from)) = rest.split_once(key) {
            let from = from.trim().split(',').next().unwrap_or_default();
            source(name, from.trim().trim_matches(['"', '\'']), line, hits);
        }
    }
    near(Ecosystem::Rubygems, name, line, hits);
}

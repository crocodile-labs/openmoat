//! Lockfiles: where each locked package is fetched from, and whether its
//! hash changes while its version stays.
//!
//! A package manager installs what the lockfile names and checks it against
//! the hash there. A lockfile edit that points a package at another host, or
//! swaps its hash for the same version, makes the next install fetch other
//! code, and no manifest line changes to show it.

use std::collections::BTreeSet;

use super::files::Lock;
use super::{Block, Change, Hit, LOCK_INTEGRITY, Level, PACKAGE_SOURCE, shown};
use crate::packages::Ecosystem;

/// The hosts each registry serves its packages from: a source there is the registry's.
fn registry_hosts(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Npm => &["registry.npmjs.org", "registry.yarnpkg.com"],
        Ecosystem::Pypi => &["files.pythonhosted.org", "pypi.org"],
        Ecosystem::Crates => &["index.crates.io", "static.crates.io", "crates.io"],
        Ecosystem::Rubygems => &["rubygems.org"],
        Ecosystem::Go => &["proxy.golang.org"],
    }
}

/// crates.io's index as `Cargo.lock` names it.
const CRATES_IO_INDEX: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// How far above a hash line a changed version still belongs to the same
/// package: `Cargo.lock` keeps `source` between `version` and `checksum`, so
/// an upgrade there is two blocks two lines apart. The entries of every
/// lockfile are longer, so a neighbour's upgrade is never this close.
const SAME_ENTRY_LINES: usize = 3;

pub(super) fn scan(lock: Lock, change: &Change<'_>, hits: &mut Vec<Hit>) {
    sources(lock, change, hits);
    let moved: Vec<usize> = change
        .blocks
        .iter()
        .filter(|b| {
            b.removed.iter().any(|t| names_version(t))
                || change.added_in(b).iter().any(|(_, t)| names_version(t))
        })
        .map(|b| b.at)
        .collect();
    for block in change.blocks {
        let version_moved = moved
            .iter()
            .any(|&at| at <= block.at && block.at - at <= SAME_ENTRY_LINES);
        integrity(change, block, version_moved, hits);
    }
}

/// The source URLs an added line names: `"resolved": "…"`, `resolved "…"`,
/// `tarball: …`, `repo: …`, `source = "…"`, `url = "…"`, `git = "…"`.
fn urls(lock: Lock, text: &str) -> Vec<String> {
    let keys: &[&str] = match lock {
        Lock::Npm => &["\"resolved\":"],
        Lock::Yarn => &["resolved ", "resolution:"],
        Lock::Pnpm => &["tarball:", "repo:"],
        Lock::Cargo => &["source ="],
        Lock::Python => &["url =", "git =", "registry ="],
    };
    keys.iter()
        .filter_map(|key| {
            let (_, rest) = text.split_once(key)?;
            let value = rest
                .trim_start()
                .trim_start_matches(['"', '\''])
                .split(['"', '\'', ',', '}', ' '])
                .next()?;
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect()
}

/// Where `url` leaves the registry: `None` when it is the registry's.
fn outside(lock: Lock, url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    if lock == Lock::Cargo
        && (lower == CRATES_IO_INDEX || lower.starts_with("sparse+https://index.crates.io"))
    {
        return None;
    }
    if lock == Lock::Yarn && !lower.contains("://") {
        // yarn 2+: `resolution: "name@npm:1.2.3"` is the registry; `name@git…`, `@http…` are not
        return ["@git", "@http", "@https", "@github:", "@ssh"]
            .iter()
            .any(|p| lower.contains(p))
            .then(|| "git or a URL".to_owned());
    }
    let git = ["git+", "git:", "git@", "ssh:", "github:"]
        .iter()
        .any(|p| lower.starts_with(p));
    if git {
        return Some("git".to_owned());
    }
    let (scheme, rest) = lower.split_once("://")?;
    let host = crate::host::of_url(rest)?;
    if scheme == "http" {
        return Some(format!("{host} over plain http"));
    }
    let registry = registry_hosts(lock.ecosystem())
        .iter()
        .any(|r| host == *r || host.ends_with(&format!(".{r}")));
    (!registry).then_some(host)
}

/// One finding per place a lockfile's packages come from outside the registry.
fn sources(lock: Lock, change: &Change<'_>, hits: &mut Vec<Hit>) {
    let mut seen = BTreeSet::new();
    for (line, text) in change.added {
        for url in urls(lock, text) {
            let Some(place) = outside(lock, &url) else {
                continue;
            };
            if seen.insert(place.clone()) {
                hits.push(Hit::new(
                    PACKAGE_SOURCE,
                    Level::Review,
                    *line,
                    format!(
                        "locks a package to {} (`{}`), not the {} registry: the next install \
                         fetches whatever is there",
                        shown(&place),
                        shown(&url),
                        lock.ecosystem().id()
                    ),
                ));
            }
        }
    }
}

/// A hash a lockfile line holds, with the file it is for when the line names
/// one (`{file = "x-1.0.tar.gz", hash = "sha256:…"}`).
struct Hash {
    value: String,
    file: Option<String>,
}

/// The hash of `text`: `"integrity": "…"`, `integrity …`, `integrity: …`,
/// `checksum = "…"`, `checksum: …`, `hash = "…"`. Not `content-hash`, which
/// poetry rewrites on every change.
fn hash_of(text: &str) -> Option<Hash> {
    let lower = text.to_ascii_lowercase();
    let (at, key) = ["integrity", "checksum", "hash"].iter().find_map(|key| {
        let at = lower.match_indices(key).map(|(i, _)| i).find(|&i| {
            let before = lower[..i].chars().next_back();
            !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })?;
        Some((at, *key))
    })?;
    let rest = text[at + key.len()..]
        .trim_start_matches(['"', '\''])
        .trim_start()
        .trim_start_matches([':', '='])
        .trim_start()
        .trim_start_matches(['"', '\'']);
    let value: String = rest
        .chars()
        .take_while(|c| !matches!(c, '"' | '\'' | ',' | '}' | ' '))
        .collect();
    if value.len() < 16 {
        return None;
    }
    let file = ["file = \"", "url = \""].iter().find_map(|key| {
        let (_, rest) = text.split_once(key)?;
        let name = rest.split('"').next()?;
        Some(name.rsplit('/').next().unwrap_or(name).to_owned())
    });
    Some(Hash { value, file })
}

/// Whether `text` gives a locked package's version: `"version":`,
/// `version "…"`, `version: …`, `version = "…"`, or a pnpm or yarn key with
/// one (`lodash@4.17.21:`).
fn names_version(text: &str) -> bool {
    let t = text.trim().trim_start_matches('"');
    t.starts_with("version\"")
        || t.starts_with("version ")
        || t.starts_with("version:")
        || t.starts_with("version=")
        || (t.ends_with(':')
            && t.match_indices('@')
                .any(|(i, _)| t[i + 1..].starts_with(|c: char| c.is_ascii_digit())))
}

/// A hash `block` removes that comes back different, or not at all, while the
/// package's version stays (`version_moved` is false).
fn integrity(change: &Change<'_>, block: &Block, version_moved: bool, hits: &mut Vec<Hit>) {
    let added = change.added_in(block);
    let removed: Vec<Hash> = block.removed.iter().filter_map(|t| hash_of(t)).collect();
    if removed.is_empty() {
        return;
    }
    let new: Vec<(usize, Hash)> = added
        .iter()
        .filter_map(|(n, t)| Some((*n, hash_of(t)?)))
        .collect();
    let mut reported = false;
    for old in &removed {
        if new.iter().any(|(_, h)| h.value == old.value) {
            continue;
        }
        let same_file = new
            .iter()
            .find(|(_, h)| h.file.is_some() && h.file == old.file);
        let line = match (&old.file, same_file) {
            // a file's hash replaced for the same file name: its version stayed
            (Some(_), Some((line, _))) => *line,
            (Some(_), None) => continue,
            (None, _) if version_moved => continue,
            (None, _) => new.first().map_or(block.at, |(line, _)| *line),
        };
        if reported {
            continue;
        }
        reported = true;
        let what = if new.is_empty() {
            "removes a package's integrity hash"
        } else {
            "changes a package's integrity hash"
        };
        hits.push(Hit::new(
            LOCK_INTEGRITY,
            Level::Deny,
            line,
            format!(
                "{what} while its version stays: the next install accepts other code under the \
                 same version (an older npm rewriting sha1 to sha512 does this too; check the \
                 registry's hash)"
            ),
        ));
    }
}

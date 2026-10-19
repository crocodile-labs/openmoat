//! Package names, and whether one is a near miss of a popular package (ADR-030).
//!
//! Each registry has a bundled list of its most-installed names
//! (`data/top-packages/<ecosystem>.txt`). Nothing is looked up online. A name
//! that is not on its list but is one typo or a common trick away from a name
//! that is (`reqeusts` for `requests`, `lodahs` for `lodash`, `python-redis`
//! for `redis`) is a near miss: what a typo-squat or a package name an agent
//! made up looks like. Every other name, unknown ones included, is normal.

use std::collections::HashSet;
use std::sync::LazyLock;

/// A package registry whose installs the shell classifier recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// The npm registry (`npm`, `pnpm`, `yarn`, `bun`).
    Npm,
    /// The Python Package Index (`pip`, `uv`, `poetry`, `pipx`).
    Pypi,
    /// crates.io (`cargo add`, `cargo install`).
    Crates,
    /// rubygems.org (`gem install`).
    Rubygems,
    /// Go modules (`go get`, `go install`).
    Go,
}

/// Names shorter than this (after normalising) are never near misses: among
/// short names one letter is the whole difference between two real packages.
const MIN_LEN: usize = 5;

impl Ecosystem {
    /// The id used in atoms and reasons.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Crates => "crates",
            Self::Rubygems => "rubygems",
            Self::Go => "go",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Npm => 0,
            Self::Pypi => 1,
            Self::Crates => 2,
            Self::Rubygems => 3,
            Self::Go => 4,
        }
    }

    fn list(self) -> &'static str {
        match self {
            Self::Npm => include_str!("../data/top-packages/npm.txt"),
            Self::Pypi => include_str!("../data/top-packages/pypi.txt"),
            Self::Crates => include_str!("../data/top-packages/crates.txt"),
            Self::Rubygems => include_str!("../data/top-packages/rubygems.txt"),
            Self::Go => include_str!("../data/top-packages/go.txt"),
        }
    }

    /// Words squatters put before and after a popular name (`node-`, `-js`,
    /// `python-`, `-rs`), in normalised form.
    fn affixes(self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Self::Npm => (
                &["node-", "nodejs-", "js-"],
                &["-js", ".js", "js", "-node", "-nodejs"],
            ),
            Self::Pypi => (&["python-", "python3-", "py-", "py"], &["-python", "-py"]),
            Self::Crates => (&["rust-", "rs-"], &["-rs", "-rust"]),
            Self::Rubygems => (&["ruby-"], &["-ruby", "-rb", ".rb"]),
            Self::Go => (&[], &[]),
        }
    }

    /// The name as the registry compares names: the Python index folds case and treats
    /// runs of `-`, `_` and `.` as one `-` (PEP 503); crates.io folds case and
    /// `_` into `-`; a Go module's major version suffix (`/v2`) is dropped.
    #[must_use]
    pub fn normalise(self, name: &str) -> String {
        let lower = name.to_ascii_lowercase();
        match self {
            Self::Pypi => {
                let mut out = String::with_capacity(lower.len());
                for c in lower.chars() {
                    if matches!(c, '-' | '_' | '.') {
                        if !out.ends_with('-') {
                            out.push('-');
                        }
                    } else {
                        out.push(c);
                    }
                }
                out
            }
            Self::Crates => lower.replace('_', "-"),
            Self::Go => match lower.rsplit_once("/v") {
                Some((module, major))
                    if !major.is_empty() && major.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    module.to_owned()
                }
                _ => lower,
            },
            Self::Npm | Self::Rubygems => lower,
        }
    }
}

/// One ecosystem's list: names in popularity order, normalised and as written.
struct Top {
    names: Vec<(String, &'static str)>,
    known: HashSet<String>,
}

impl Top {
    fn load(ecosystem: Ecosystem) -> Self {
        let names: Vec<(String, &'static str)> = ecosystem
            .list()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| (ecosystem.normalise(l), l))
            .collect();
        let known = names.iter().map(|(n, _)| n.clone()).collect();
        Self { names, known }
    }
}

static TOP: LazyLock<[Top; 5]> = LazyLock::new(|| {
    [
        Ecosystem::Npm,
        Ecosystem::Pypi,
        Ecosystem::Crates,
        Ecosystem::Rubygems,
        Ecosystem::Go,
    ]
    .map(Top::load)
});

/// How many names the bundled list of `ecosystem` holds.
#[cfg(test)]
fn list_len(ecosystem: Ecosystem) -> usize {
    TOP[ecosystem.index()].names.len()
}

/// The popular package `name` is a near miss of, if it is one: `name` is not
/// on the list, and a listed name of at least five characters is one edit
/// away (a letter added, dropped, changed or two swapped), differs only in
/// `-`, `_` and `.` or in doubled letters, or is `name` with a squatter's
/// prefix or suffix added or removed. The most popular such name is returned.
#[must_use]
pub fn near_miss(ecosystem: Ecosystem, name: &str) -> Option<&'static str> {
    let top = &TOP[ecosystem.index()];
    let key = ecosystem.normalise(name);
    if !key.is_ascii() || top.known.contains(&key) {
        return None;
    }
    let (prefixes, suffixes) = ecosystem.affixes();
    let stripped = without_separators(&key);
    let collapsed = collapse_runs(&key);
    top.names
        .iter()
        .filter(|(popular, _)| popular.len() >= MIN_LEN)
        .find(|(popular, _)| {
            (stripped.len() >= MIN_LEN && stripped == without_separators(popular))
                || (collapsed.len() >= MIN_LEN && collapsed == collapse_runs(popular))
                || one_edit(&key, popular)
                || affixed(&key, popular, prefixes, suffixes)
                || (key.len() >= MIN_LEN && affixed(popular, &key, prefixes, suffixes))
        })
        .map(|(_, written)| *written)
}

fn without_separators(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .collect()
}

/// `name` with each run of one character kept once (`expresss` → `expres`).
fn collapse_runs(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if !out.ends_with(c) {
            out.push(c);
        }
    }
    out
}

/// Whether `long` is `base` with one of the prefixes or suffixes added.
fn affixed(long: &str, base: &str, prefixes: &[&str], suffixes: &[&str]) -> bool {
    prefixes
        .iter()
        .any(|p| long.strip_prefix(p).is_some_and(|rest| rest == base))
        || suffixes
            .iter()
            .any(|s| long.strip_suffix(s).is_some_and(|rest| rest == base))
}

/// Whether `a` and `b` differ by exactly one insertion, deletion, substitution
/// or swap of two neighbouring characters (optimal string alignment distance 1).
fn one_edit(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a == b || a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let (a, b) = (&a[prefix..], &b[prefix..]);
    match (a.len(), b.len()) {
        (n, m) if n == m => {
            // one substitution, or one swap of neighbours
            a[1..] == b[1..] || (n >= 2 && a[0] == b[1] && a[1] == b[0] && a[2..] == b[2..])
        }
        (n, m) if n > m => a[1..] == *b,
        _ => *a == b[1..],
    }
}

#[cfg(test)]
mod tests;

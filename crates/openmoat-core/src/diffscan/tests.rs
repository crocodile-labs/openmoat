//! Each content check against an attack and against the benign changes of
//! daily work that look nearest to it.

use super::{Block, Change, Hit, Level, RULES, Settings, rule, scan};
use crate::Policy;

mod ci;
mod code;
mod hosts;
mod supply;

/// One file of a change, owned, for building a [`Change`].
pub(super) struct File {
    path: String,
    added: Vec<(usize, String)>,
    blocks: Vec<Block>,
}

impl File {
    /// `path` with one block that removes `removed` and adds `added` at line 10.
    pub(super) fn edit(path: &str, removed: &[&str], added: &[&str]) -> Self {
        let mut file = Self {
            path: path.to_owned(),
            added: Vec::new(),
            blocks: Vec::new(),
        };
        file.block(removed, added);
        file
    }

    /// `path` as a new file holding `lines`.
    pub(super) fn new(path: &str, lines: &[&str]) -> Self {
        Self::edit(path, &[], lines)
    }

    /// Another block, after a kept line.
    pub(super) fn block(&mut self, removed: &[&str], added: &[&str]) -> &mut Self {
        let at = self.added.last().map_or(10, |(n, _)| n + 2);
        let start = self.added.len();
        self.added.extend(
            added
                .iter()
                .enumerate()
                .map(|(i, t)| (at + i, (*t).to_owned())),
        );
        self.blocks.push(Block {
            at,
            removed: removed.iter().map(|t| (*t).to_owned()).collect(),
            added: start..self.added.len(),
        });
        self
    }

    pub(super) fn change(&self) -> Change<'_> {
        Change {
            path: &self.path,
            added: &self.added,
            blocks: &self.blocks,
        }
    }

    pub(super) fn hits(&self) -> Vec<Hit> {
        scan(&self.change())
    }
}

/// The `(rule, level)` of each hit of `file`.
pub(super) fn found(file: &File) -> Vec<(&'static str, Level)> {
    file.hits().iter().map(|h| (h.rule, h.level)).collect()
}

/// `file` has no content finding.
pub(super) fn quiet(file: &File) {
    let hits = file.hits();
    assert!(hits.is_empty(), "{}: {hits:#?}", file.path);
}

#[test]
fn every_rule_id_is_unique_stable_and_documented_once() {
    let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), RULES.len());
    for r in RULES {
        assert!(r.id.starts_with("diff-"), "{}", r.id);
        assert_ne!(r.level, Level::Off, "{}", r.id);
        assert!(rule(r.id).is_some());
    }
    let docs = include_str!("../../../../docs/MERGE_CHECK.md");
    for r in RULES {
        assert!(
            docs.contains(&format!("`{}`", r.id)),
            "MERGE_CHECK.md misses {}",
            r.id
        );
    }
}

#[test]
fn the_policy_sets_levels_and_rejects_unknown_rules() {
    let policy = Policy::parse(
        "version: 1\ncheck_diff:\n  levels:\n    diff-ci-unpinned: off\n    diff-new-host: deny\n",
    )
    .unwrap();
    let settings = policy.check_diff.as_ref();
    let hit = |rule| Hit {
        rule,
        level: Level::Review,
        line: Some(1),
        reason: String::new(),
    };
    assert_eq!(
        Settings::level(settings, &hit(super::CI_UNPINNED)),
        Level::Off
    );
    assert_eq!(
        Settings::level(settings, &hit(super::NEW_HOST)),
        Level::Deny
    );
    assert_eq!(
        Settings::level(settings, &hit(super::ENV_SECRET)),
        Level::Review
    );
    assert_eq!(
        Settings::level(None, &hit(super::ENV_SECRET)),
        Level::Review
    );
    let warnings = crate::lint::warnings(&policy);
    assert!(
        warnings
            .iter()
            .any(|w| w.rule == "check_diff.levels.diff-ci-unpinned"),
        "{warnings:?}"
    );
    let unknown = Policy::parse("version: 1\ncheck_diff:\n  levels:\n    diff-nope: off\n");
    assert!(
        unknown
            .unwrap_err()
            .to_string()
            .contains("check_diff.levels.diff-nope")
    );
    assert!(
        Policy::parse("version: 1\ncheck_diff:\n  levels:\n    diff-new-host: loud\n").is_err()
    );
    assert!(Policy::parse("version: 1\ncheck_diff:\n  level: {}\n").is_err());
}

#[test]
fn a_plain_source_edit_is_quiet() {
    quiet(&File::edit(
        "src/main.rs",
        &["fn main() {}"],
        &["fn main() {", "    run(\"hello\");", "}"],
    ));
    quiet(&File::edit(
        "README.md",
        &[],
        &["Run `curl -sSf https://sh.rustup.rs | sh` first."],
    ));
}

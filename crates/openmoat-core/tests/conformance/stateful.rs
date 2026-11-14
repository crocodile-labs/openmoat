//! The threat classes of `docs/THREAT_MODEL.md` §3 that no conformance fixture
//! is tagged with, because one tool call cannot show them: a push is checked
//! against the commits it sends, a pull request against its diff, and injected
//! input against what an earlier call returned. `docs/COVERAGE.md` lists them
//! with zero tagged fixtures, the tests that do exercise them and the fixtures
//! of other classes that carry their rule, so the table never reads as if
//! they were covered by fixtures, nor as if they were not tested at all.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// One class without tagged fixtures.
pub(super) struct Class {
    pub(super) id: &'static str,
    pub(super) name: &'static str,
    /// Why a single-call fixture cannot test it.
    why: &'static str,
    /// Files or directories, from the repository root, whose `#[test]`s exercise it.
    tests: &'static [&'static str],
    /// Rules that decide it: fixtures of other classes that expect one are listed.
    rules: &'static [&'static str],
}

/// T13 to T15, in `docs/THREAT_MODEL.md` §3's order.
pub(super) const CLASSES: [Class; 3] = [
    Class {
        id: "T13",
        name: "Publishing through a push",
        why: "the push check reads the commits a `git push` or `gh pr create` would send, which \
              a single call does not carry",
        tests: &["crates/openmoat-cli/tests/e2e/push.rs"],
        rules: &["push-secret", "push-runs-later", "push-unchecked"],
    },
    Class {
        id: "T14",
        name: "A backdoor in a pull request",
        why: "`openmoat policy check-diff` reads a diff, not a tool call",
        tests: &[
            "crates/openmoat-cli/tests/e2e/check_diff.rs",
            "crates/openmoat-core/src/diffscan/tests.rs",
            "crates/openmoat-core/src/diffscan/tests",
        ],
        rules: &[],
    },
    Class {
        id: "T15",
        name: "Acting on injected input",
        why: "a call is linked to what an earlier call returned; the fixtures that carry the \
              rule are tagged with the class of what the planted call does",
        tests: &[
            "crates/openmoat-cli/tests/e2e/injected.rs",
            "crates/openmoat-cli/tests/e2e/injected_hosts.rs",
            "crates/openmoat-cli/tests/e2e/mcp_gateway/injected.rs",
        ],
        rules: &["injected-input"],
    },
];

/// Every `.rs` file at `path`: the file itself, or each one under a directory.
fn rust_files(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        out.push(path.to_owned());
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.map(|e| e.unwrap().path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// The number of `#[test]` functions under `class.tests`, or why the list is wrong.
fn test_count(root: &Path, class: &Class) -> Result<usize, String> {
    let mut total = 0;
    for rel in class.tests {
        let mut files = Vec::new();
        rust_files(&root.join(rel), &mut files);
        let count: usize = files
            .iter()
            .map(|f| {
                fs::read_to_string(f)
                    .unwrap()
                    .lines()
                    .filter(|l| l.trim() == "#[test]")
                    .count()
            })
            .sum();
        if count == 0 {
            return Err(format!("{}: `{rel}` holds no test", class.id));
        }
        total += count;
    }
    Ok(total)
}

/// The `docs/COVERAGE.md` table rows of these classes: no tagged fixture.
pub(super) fn rows() -> String {
    let mut out = String::new();
    for c in &CLASSES {
        let _ = writeln!(out, "| {} | {} | — | 0 | 0 | 0 |", c.id, c.name);
    }
    out
}

/// The `docs/COVERAGE.md` section on these classes. `carrying(rule)` gives
/// each fixture (id, file, class) that expects `rule`.
pub(super) fn section(
    root: &Path,
    carrying: impl Fn(&str) -> Vec<(String, String, String)>,
) -> Result<String, Vec<String>> {
    let mut out = String::from(
        "\n## Classes no fixture is tagged with\n\n\
         T13 to T15 have no fixture tagged with them: a fixture is one tool call, and these \
         are decided from more than one. They are tested by the end-to-end and unit tests \
         named below, not by conformance fixtures, and they have no OWASP column above.\n",
    );
    let mut problems = Vec::new();
    for c in &CLASSES {
        let _ = write!(out, "\n### {}: {}\n\n", c.id, c.name);
        let _ = writeln!(out, "- Tagged fixtures: none; {}.", c.why);
        match test_count(root, c) {
            Ok(n) => {
                let files = c
                    .tests
                    .iter()
                    .map(|t| format!("`{t}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(out, "- Tests ({n}): {files}");
            }
            Err(e) => problems.push(e),
        }
        for rule in c.rules {
            let found = carrying(rule);
            let list = if found.is_empty() {
                "none".to_owned()
            } else {
                found
                    .iter()
                    .map(|(id, file, class)| format!("`{id}` ({file}, {class})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let _ = writeln!(
                out,
                "- Fixtures of other classes expecting `{rule}` ({}): {list}",
                found.len()
            );
        }
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(problems)
    }
}

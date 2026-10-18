//! What the commits of a push add: the lines each commit's diff adds and each
//! commit message, searched for known token shapes and brokered secret
//! values, and the files the commits change, for `runs-later` files.
//!
//! Lines a diff removes or keeps are not searched: a kept line is in a parent
//! commit, which is either in the push (searched there) or already on the
//! remote. A merge commit's diff is taken against its first parent, so a
//! value added while resolving a merge is seen. Binary files are not searched.

use openmoat_audit::{KnownSecrets, token_shape};

use super::git::{Git, Unchecked};
use crate::sandbox::RUNS_LATER;

/// At most this much of the commits' diffs is read; a push that changes more
/// asks instead of being checked in part.
pub const MAX_DIFF_BYTES: usize = 8 * 1024 * 1024;
/// At most this much of the commit messages and of the changed file names.
const MAX_LIST_BYTES: usize = 1024 * 1024;

/// Marks the line that starts one commit in `git log` output.
const COMMIT: char = '\u{1}';

/// What the commits of a push add.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// The first token or secret value found: where and what, never the value.
    pub secret: Option<String>,
    /// Changed files that CI, a hook manager, the editor or the agent host
    /// runs later; listed only when `with_files` was asked for.
    pub runs_later: Vec<String>,
}

/// Search the commits `revs` lists. `with_files` also lists the `runs-later`
/// files they change.
pub fn scan(
    git: &Git,
    revs: &[String],
    known: &KnownSecrets,
    with_files: bool,
) -> Result<Found, Unchecked> {
    let mut found = Found::default();
    let messages = log(git, &["--format=%x01%h%n%B"], revs, MAX_LIST_BYTES)?;
    found.secret = search(&messages, known, false);
    if found.secret.is_some() {
        return Ok(found);
    }
    let diffs = log(
        git,
        &[
            "-p",
            "--format=%x01%h",
            "--no-ext-diff",
            "--no-textconv",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--no-relative",
            "--diff-merges=first-parent",
        ],
        revs,
        MAX_DIFF_BYTES,
    )?;
    found.secret = search(&diffs, known, true);
    if found.secret.is_some() || !with_files {
        return Ok(found);
    }
    let names = log(
        git,
        &[
            "--format=",
            "--name-only",
            "-z",
            "--diff-merges=first-parent",
        ],
        revs,
        MAX_LIST_BYTES,
    )?;
    for name in names.split(['\0', '\n']).map(str::trim) {
        if !name.is_empty() && runs_later(name) && !found.runs_later.iter().any(|n| n == name) {
            found.runs_later.push(name.to_owned());
        }
    }
    Ok(found)
}

/// `git log <options> <revs>` as text, refused past `limit` bytes.
fn log(git: &Git, options: &[&str], revs: &[String], limit: usize) -> Result<String, Unchecked> {
    let mut args = vec!["log", "--no-color", "--no-renames", "--no-mailmap"];
    args.extend_from_slice(options);
    args.extend(revs.iter().map(String::as_str));
    let out = git.run(&args, limit)?;
    if out.cut {
        return Err(Unchecked(format!(
            "the push changes more than {} MiB, more than OpenMoat reads",
            limit / (1024 * 1024)
        )));
    }
    if !out.ok {
        return Err(Unchecked("git could not list the commits".to_owned()));
    }
    Ok(String::from_utf8_lossy(&out.bytes).into_owned())
}

/// The first secret in `text`, a `git log` listing. In a diff (`diff`), only
/// added lines count, and the file each is in is named.
fn search(text: &str, known: &KnownSecrets, diff: bool) -> Option<String> {
    let mut commit = "";
    let mut file = "";
    for line in text.lines() {
        if let Some(id) = line.strip_prefix(COMMIT) {
            commit = id.trim();
            continue;
        }
        let added = if diff {
            if let Some(path) = line.strip_prefix("+++ ") {
                file = path.strip_prefix("b/").unwrap_or(path);
                continue;
            }
            match line.strip_prefix('+') {
                Some(added) => added,
                None => continue,
            }
        } else {
            line
        };
        let what = match token_shape(added) {
            Some(shape) => shape,
            None if known.occurs_in(added) => "the value of a brokered secret (`secrets:`)",
            None => continue,
        };
        return Some(if diff {
            format!("commit {commit} adds {what} to {file}")
        } else {
            format!("the message of commit {commit} holds {what}")
        });
    }
    None
}

/// Whether `path`, relative to the repository, is one of [`RUNS_LATER`] at any
/// depth. Letter case is ignored: stricter on a file system that ignores it.
pub fn runs_later(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    RUNS_LATER.iter().any(|pattern| {
        let file = pattern.trim_start_matches("**/").to_ascii_lowercase();
        match file.strip_suffix("/**") {
            Some(dir) => path.starts_with(&format!("{dir}/")) || path.contains(&format!("/{dir}/")),
            None => path == file || path.ends_with(&format!("/{file}")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{runs_later, search};
    use openmoat_audit::KnownSecrets;

    #[test]
    fn runs_later_files_at_any_depth() {
        for path in [
            ".github/workflows/ci.yml",
            "sub/.github/workflows/x/y.yaml",
            ".gitlab-ci.yml",
            "a/Jenkinsfile",
            ".husky/pre-commit",
            ".claude/hooks/h.sh",
            ".mcp.json",
            ".GitHub/Workflows/ci.yml",
        ] {
            assert!(runs_later(path), "{path}");
        }
        for path in [
            "src/main.rs",
            ".github/CODEOWNERS",
            "x.mcp.json",
            "Jenkinsfile.md",
        ] {
            assert!(!runs_later(path), "{path}");
        }
    }

    #[test]
    fn only_added_lines_count_and_the_value_is_never_named() {
        // Generated for the test; no real secret is used.
        let fake = "q7Zp-fake-9xK2mW4v";
        let known = KnownSecrets::new([fake]).unwrap();
        let diff = format!(
            "\u{1}abc1234\n\ndiff --git a/k b/k\n--- a/k\n+++ b/k\n-old {fake}\n {fake}\n+fine\n"
        );
        assert_eq!(search(&diff, &known, true), None);
        let diff = format!("\u{1}abc1234\n+++ b/conf/k.env\n+KEY={fake}\n");
        let found = search(&diff, &known, true).unwrap();
        assert_eq!(
            found,
            "commit abc1234 adds the value of a brokered secret (`secrets:`) to conf/k.env"
        );
        // Built at run time, so a push of this file holds no token-shaped line.
        let message = format!("\u{1}def5678\n- AKIA{} was rotated\n", "FAKE0EXAMPLE0000");
        let found = search(&message, &KnownSecrets::default(), false).unwrap();
        assert_eq!(
            found,
            "the message of commit def5678 holds an AWS access key id"
        );
    }
}

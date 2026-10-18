//! Which commits a push would publish: what it sends, minus what the remote
//! is known to have.
//!
//! - What it sends: the source of each refspec (`git push origin a b:c`), every
//!   branch for `--all`, `--branches`, `--mirror` or a glob refspec, every tag
//!   for `--tags` or `--mirror`, and `HEAD` when none is named (also for
//!   `gh pr create`). Deletions send nothing.
//! - What the remote has: with no refspec, the current branch's upstream
//!   (`@{u}`). Otherwise, or without an upstream, the remote's default branch
//!   (`refs/remotes/<remote>/HEAD`); when that is not set, every branch of the
//!   remote that git knows of; for a URL or a path instead of a remote's
//!   name, every remote-tracking branch. A remote git knows nothing of has
//!   nothing, so the whole history is checked.

use super::git::{Git, Unchecked};

/// What a push command names, read from its arguments.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Spec {
    /// The remote's name, URL or path, if the command names one.
    pub remote: Option<String>,
    /// Sources of the refspecs that send something.
    pub sources: Vec<String>,
    /// Every local branch is sent.
    pub branches: bool,
    /// Every tag is sent.
    pub tags: bool,
    /// The command only deletes remote refs.
    pub deletes: bool,
}

/// `git push` options whose value is the next word unless given with `=`.
const VALUED: &[&str] = &["-o", "--push-option", "--repo", "--receive-pack", "--exec"];

/// Read `argv` (`git push …` or `gh pr create …`).
pub fn spec(argv: &[String]) -> Spec {
    let mut spec = Spec::default();
    if argv.get(1).map(String::as_str) != Some("push") {
        return spec;
    }
    let mut positional = Vec::new();
    let mut words = argv[2..].iter();
    let mut options = true;
    while let Some(word) = words.next() {
        if options && word == "--" {
            options = false;
        } else if options && word.starts_with('-') {
            match word.as_str() {
                "--all" | "--branches" => spec.branches = true,
                "--mirror" => (spec.branches, spec.tags) = (true, true),
                "--tags" => spec.tags = true,
                "-d" | "--delete" => spec.deletes = true,
                "--repo" => spec.remote = words.next().cloned(),
                w if VALUED.contains(&w) => {
                    words.next();
                }
                w => {
                    if let Some(repo) = w.strip_prefix("--repo=") {
                        spec.remote = Some(repo.to_owned());
                    }
                }
            }
        } else {
            positional.push(word);
        }
    }
    let mut positional = positional.into_iter();
    if let Some(remote) = positional.next() {
        spec.remote = Some(remote.clone());
    }
    for refspec in positional {
        if spec.deletes {
            break;
        }
        let refspec = refspec.strip_prefix('+').unwrap_or(refspec);
        let source = refspec.split_once(':').map_or(refspec, |(src, _)| src);
        if source.is_empty() {
            continue;
        }
        if source.contains('*') {
            spec.branches = true;
        } else {
            spec.sources.push(source.to_owned());
        }
    }
    spec
}

/// The revisions for `git log` that list the commits `spec` publishes from
/// the repository `git` runs in: commit ids, then `--not` and what the remote
/// has. `None` when there is nothing to check: not a repository, nothing
/// committed yet, or only deletions.
pub fn revisions(git: &Git, spec: &Spec) -> Result<Option<Vec<String>>, Unchecked> {
    if spec.deletes || git.value(&["rev-parse", "--git-dir"])?.is_none() {
        return Ok(None);
    }
    let named = !spec.sources.is_empty() || spec.branches || spec.tags;
    let mut revs = Vec::new();
    if spec.branches {
        revs.push("--branches".to_owned());
    }
    if spec.tags {
        revs.push("--tags".to_owned());
    }
    if named {
        for source in &spec.sources {
            if source.starts_with('-') {
                return Err(Unchecked(format!("`{source}` is not a refspec git reads")));
            }
            let Some(id) = commit(git, source)? else {
                return Err(Unchecked(format!(
                    "which commit `{source}` names is not known"
                )));
            };
            revs.push(id);
        }
    } else {
        // Nothing committed yet: the push fails, nothing is published.
        let Some(head) = commit(git, "HEAD")? else {
            return Ok(None);
        };
        revs.push(head);
    }
    revs.push("--not".to_owned());
    if !named && let Some(upstream) = commit(git, "@{u}")? {
        revs.push(upstream);
        return Ok(Some(revs));
    }
    let remote = match &spec.remote {
        Some(remote) => remote.clone(),
        None => branch_remote(git)?,
    };
    let known = git
        .value(&["config", "--get", &format!("remote.{remote}.url")])?
        .is_some();
    if !known {
        revs.push("--remotes".to_owned());
    } else if let Some(default) = commit(git, &format!("refs/remotes/{remote}/HEAD"))? {
        revs.push(default);
    } else {
        revs.push(format!("--remotes={remote}"));
    }
    Ok(Some(revs))
}

/// The remote the current branch pushes to by default, in git's order:
/// `branch.<b>.pushRemote`, `remote.pushDefault`, `branch.<b>.remote`, `origin`.
fn branch_remote(git: &Git) -> Result<String, Unchecked> {
    let branch = git.value(&["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    let mut keys = Vec::new();
    if let Some(b) = &branch {
        keys.push(format!("branch.{b}.pushRemote"));
    }
    keys.push("remote.pushDefault".to_owned());
    if let Some(b) = &branch {
        keys.push(format!("branch.{b}.remote"));
    }
    for key in keys {
        if let Some(remote) = git.value(&["config", "--get", &key])? {
            return Ok(remote);
        }
    }
    Ok("origin".to_owned())
}

/// The commit `name` names, if any.
fn commit(git: &Git, name: &str) -> Result<Option<String>, Unchecked> {
    git.value(&[
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        &format!("{name}^{{commit}}"),
    ])
}

#[cfg(test)]
mod tests;

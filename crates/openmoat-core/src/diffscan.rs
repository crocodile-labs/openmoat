//! What the added lines of a change do (ADR-055): the content checks of
//! `openmoat policy check-diff`, on top of its path checks (ADR-050).
//!
//! Each check is a pure function over one changed file: its path, the lines
//! it adds with their numbers in the new file, and the blocks of lines it
//! removes and adds together ([`Block`]). Nothing is read from disk or the
//! network: the same change gives the same findings on every machine.
//!
//! - Supply chain (`manifest.rs`, `lockfile.rs`): a new dependency that is a
//!   near miss of a popular name (the bundled lists of `packages.rs`,
//!   the ones the shell classifier uses), an npm install script, a dependency
//!   or a locked package fetched from outside its registry, and a lockfile
//!   hash that changes while the version stays.
//! - CI takeover (`ci.rs`): GitHub workflow and action files.
//! - Backdoors (`backdoor.rs`): a downloaded or decoded script that runs, a
//!   Python start-up file, a Dockerfile `ADD` from a URL, a long encoded blob
//!   in source code.
//! - Secrets (`keys.rs`): a private key, a real-looking value in a `.env`
//!   file. Known token formats are the push check's scanner, which the CLI
//!   already runs on every added line (`diff-secret`).
//! - New network endpoints (`hosts.rs`): one finding per host the change adds
//!   that the policy's network allow list does not name; the caller decides
//!   that with the compiled policy ([`new_hosts`]).
//!
//! Every rule is in [`RULES`], with its default level; the policy's
//! `check_diff.levels` ([`Settings`]) sets another one, or `off`.

use std::collections::BTreeMap;
use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::policy::PolicyError;

mod backdoor;
mod ci;
mod files;
mod hosts;
mod keys;
mod lockfile;
mod manifest;

pub use hosts::new_hosts;

/// How much a content finding holds up a merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Not reported: only `check_diff.levels` sets this.
    Off,
    /// A person should look before it is merged.
    Review,
    /// Fails the check: what a change should never do unnoticed.
    Deny,
}

/// One content check: its stable id, the level it reports at, and what it finds.
#[derive(Debug)]
pub struct Rule {
    /// The id findings carry (`diff-ci-unpinned`); stable, like the policy's rule ids.
    pub id: &'static str,
    /// The level of its findings when the policy does not set one. A rule
    /// whose findings differ (a key in a test fixture) gives the stricter one here.
    pub level: Level,
    /// What it looks for, for docs and `--format json` readers.
    pub summary: &'static str,
}

/// A dependency name one typo or trick away from a popular package's.
pub const PACKAGE_NEAR_MISS: &str = "diff-package-near-miss";
/// An npm `preinstall`, `install` or `postinstall` script.
pub const INSTALL_SCRIPT: &str = "diff-install-script";
/// A dependency or a locked package fetched from git, plain http or another host.
pub const PACKAGE_SOURCE: &str = "diff-package-source";
/// A lockfile hash changed or removed while the package's version stays.
pub const LOCK_INTEGRITY: &str = "diff-lock-integrity";
/// `pull_request_target`, and with it a checkout of the pull request's code.
pub const CI_PR_TARGET: &str = "diff-ci-pr-target";
/// `permissions: write-all` or a write scope.
pub const CI_PERMISSIONS: &str = "diff-ci-permissions";
/// `uses:` an action at a tag or branch, not a full commit SHA.
pub const CI_UNPINNED: &str = "diff-ci-unpinned";
/// `${{ github.event.* }}`, `${{ inputs.* }}` or `${{ github.head_ref }}` inside a script.
pub const CI_INJECTION: &str = "diff-ci-injection";
/// A secret printed into the log or handed to `curl`/`wget` in a script.
pub const CI_SECRET_OUT: &str = "diff-ci-secret-out";
/// A downloaded script piped into a shell or an interpreter.
pub const PIPE_TO_SHELL: &str = "diff-pipe-to-shell";
/// Decoded text (base64, hex, compressed) run as code.
pub const DECODE_EXEC: &str = "diff-decode-exec";
/// A `.pth` file with an `import` line, which every Python start runs.
pub const PYTHON_STARTUP: &str = "diff-python-startup";
/// A Dockerfile `ADD` of a URL without `--checksum`.
pub const DOCKER_REMOTE_ADD: &str = "diff-docker-remote-add";
/// A long base64 blob in source code.
pub const ENCODED_BLOB: &str = "diff-encoded-blob";
/// A private key (PEM or `PuTTY`).
pub const PRIVATE_KEY: &str = "diff-private-key";
/// A real-looking secret value in a `.env` file.
pub const ENV_SECRET: &str = "diff-env-secret";
/// A host the policy's network allow list does not name.
pub const NEW_HOST: &str = "diff-new-host";

/// Every content check, in the order the docs list them.
pub const RULES: &[Rule] = &[
    Rule {
        id: PACKAGE_NEAR_MISS,
        level: Level::Review,
        summary: "a new dependency whose name is one typo or trick away from a popular package's",
    },
    Rule {
        id: INSTALL_SCRIPT,
        level: Level::Review,
        summary: "an npm preinstall, install or postinstall script added or changed",
    },
    Rule {
        id: PACKAGE_SOURCE,
        level: Level::Review,
        summary: "a dependency or locked package fetched from git, plain http or a host that is not its registry",
    },
    Rule {
        id: LOCK_INTEGRITY,
        level: Level::Deny,
        summary: "a lockfile integrity hash or checksum changed or removed while the version stays",
    },
    Rule {
        id: CI_PR_TARGET,
        level: Level::Deny,
        summary: "pull_request_target with a checkout of the pull request's code (review: the trigger alone)",
    },
    Rule {
        id: CI_PERMISSIONS,
        level: Level::Review,
        summary: "permissions: write-all or a write scope added to a workflow",
    },
    Rule {
        id: CI_UNPINNED,
        level: Level::Review,
        summary: "uses: an action or image at a tag or branch instead of a full commit SHA or digest",
    },
    Rule {
        id: CI_INJECTION,
        level: Level::Deny,
        summary: "an attacker-written event field expanded inside a script (review: other event fields and inputs)",
    },
    Rule {
        id: CI_SECRET_OUT,
        level: Level::Deny,
        summary: "a secret printed into the log (review: handed to curl or wget)",
    },
    Rule {
        id: PIPE_TO_SHELL,
        level: Level::Review,
        summary: "a downloaded script piped into a shell or interpreter",
    },
    Rule {
        id: DECODE_EXEC,
        level: Level::Deny,
        summary: "base64, hex or compressed text decoded and run as code (review: in tests and fixtures)",
    },
    Rule {
        id: PYTHON_STARTUP,
        level: Level::Deny,
        summary: "a .pth file with an import line, which every Python start runs (review: in tests and fixtures)",
    },
    Rule {
        id: DOCKER_REMOTE_ADD,
        level: Level::Review,
        summary: "a Dockerfile ADD of a URL without --checksum",
    },
    Rule {
        id: ENCODED_BLOB,
        level: Level::Review,
        summary: "a base64 blob of 400 or more characters in source code",
    },
    Rule {
        id: PRIVATE_KEY,
        level: Level::Deny,
        summary: "a private key (review: in a test fixture, or marked as fake)",
    },
    Rule {
        id: ENV_SECRET,
        level: Level::Review,
        summary: "a real-looking secret value in a .env file",
    },
    Rule {
        id: NEW_HOST,
        level: Level::Review,
        summary: "a URL host in code or configuration that the policy's network allow list does not name",
    },
];

/// The rule `id` names, if it is a content check.
#[must_use]
pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

/// One run of removed and added lines with no kept line between them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Block {
    /// The new file's line number where the block sits.
    pub at: usize,
    /// The removed lines, in order.
    pub removed: Vec<String>,
    /// Indices into [`Change::added`] of the lines the block adds.
    pub added: Range<usize>,
}

/// One file a change writes, as the checks see it.
#[derive(Debug, Clone, Copy)]
pub struct Change<'a> {
    /// The path in the repository, `/`-separated.
    pub path: &'a str,
    /// Each added line with its number in the new file.
    pub added: &'a [(usize, String)],
    /// The blocks of the change; a file with none is checked by its added lines alone.
    pub blocks: &'a [Block],
}

impl<'a> Change<'a> {
    /// The lines `block` adds.
    fn added_in(&self, block: &Block) -> &'a [(usize, String)] {
        self.added.get(block.added.clone()).unwrap_or_default()
    }

    /// The added lines block by block, or all of them as one run when the
    /// change has no blocks.
    fn runs(&self) -> Vec<&'a [(usize, String)]> {
        if self.blocks.is_empty() {
            return vec![self.added];
        }
        self.blocks
            .iter()
            .map(|b| self.added_in(b))
            .filter(|run| !run.is_empty())
            .collect()
    }
}

/// One thing a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The rule id, one of [`RULES`].
    pub rule: &'static str,
    /// The level the check gives this finding, before the policy's `check_diff.levels`.
    pub level: Level,
    /// The added line, in the new file; `None` for the file as a whole.
    pub line: Option<usize>,
    /// Why it matters, naming what was found but never a secret's value.
    pub reason: String,
}

impl Hit {
    fn new(rule: &'static str, level: Level, line: usize, reason: String) -> Self {
        Self {
            rule,
            level,
            line: Some(line),
            reason,
        }
    }
}

/// Every content finding of `change`, but [`NEW_HOST`] ([`new_hosts`]), in line order.
#[must_use]
pub fn scan(change: &Change<'_>) -> Vec<Hit> {
    let file = files::classify(change.path);
    let mut hits = Vec::new();
    if let Some(manifest) = file.manifest {
        manifest::scan(manifest, change, &mut hits);
    }
    if let Some(lock) = file.lock {
        lockfile::scan(lock, change, &mut hits);
    }
    if file.is(files::Kind::Workflow) {
        ci::scan(change, &mut hits);
    }
    if !file.is(files::Kind::Doc) && file.lock.is_none() {
        backdoor::scan(&file, change, &mut hits);
    }
    keys::scan(&file, change, &mut hits);
    hits.sort_by_key(|h| h.line);
    hits
}

/// The policy's `check_diff:` section: a level for any content check.
///
/// ```yaml
/// check_diff:
///   levels:
///     diff-ci-unpinned: off      # this team pins by tag on purpose
///     diff-new-host: deny
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Rule id ([`RULES`]) → `deny`, `review` or `off`.
    #[serde(default)]
    pub levels: BTreeMap<String, Level>,
}

impl Settings {
    /// The level `hit` is reported at: the policy's for its rule, else the check's own.
    #[must_use]
    pub fn level(settings: Option<&Self>, hit: &Hit) -> Level {
        settings
            .and_then(|s| s.levels.get(hit.rule))
            .copied()
            .unwrap_or(hit.level)
    }

    /// The rules the policy turns off, for `policy lint` to warn about.
    pub fn turned_off(&self) -> impl Iterator<Item = &str> {
        self.levels
            .iter()
            .filter(|(_, l)| **l == Level::Off)
            .map(|(id, _)| id.as_str())
    }
}

/// Every id under `check_diff.levels` names a content check.
pub(crate) fn check(settings: Option<&Settings>) -> Result<(), PolicyError> {
    let Some(unknown) = settings
        .into_iter()
        .flat_map(|s| s.levels.keys())
        .find(|id| rule(id).is_none())
    else {
        return Ok(());
    };
    let known: Vec<&str> = RULES.iter().map(|r| r.id).collect();
    Err(PolicyError::Rule {
        rule: format!("check_diff.levels.{unknown}"),
        problem: format!("not a check-diff content rule; one of {}", known.join(", ")),
    })
}

/// `text` for a reason: control characters dropped, at most 80 characters.
fn shown(text: &str) -> String {
    let clean: String = text.trim().chars().filter(|c| !c.is_control()).collect();
    match clean.char_indices().nth(80) {
        Some((cut, _)) => format!("{}…", &clean[..cut]),
        None => clean,
    }
}

#[cfg(test)]
mod tests;

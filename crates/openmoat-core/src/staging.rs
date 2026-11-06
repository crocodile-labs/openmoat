//! The policy's `staging:` section (ADR-061, proposed): when a session counts
//! as having collected files outside the project, so that a later send of
//! data carries the `@staging-egress <host>` atom. The engine folds the
//! session's collection in `engine/staging.rs`; no default rule names the atom
//! yet, so it is recorded and changes no decision until a policy names it.

use serde::{Deserialize, Serialize};

use crate::pattern::GlobPattern;
use crate::policy::PolicyError;

/// Outside reads after which a send with a body carries the atom, by default.
pub const DEFAULT_OUTSIDE_READS: u32 = 25;

/// Outside folders read after which a send with a body carries the atom, by default.
pub const DEFAULT_OUTSIDE_FOLDERS: u32 = 2;

/// Where reads never count as collection: dependency caches and toolchains an
/// agent reads to build, and the agent's own temporary folder (Claude Code's
/// `/tmp/claude-<uid>`). Not the whole of `/tmp`: a home or a project can be
/// below a temporary folder, and what is read there is no less collected.
pub(crate) const IGNORED: &[&str] = &[
    "~/.cargo/registry/**",
    "~/.cargo/git/**",
    "~/.rustup/**",
    "~/go/pkg/mod/**",
    "~/.m2/repository/**",
    "~/.gradle/caches/**",
    "~/.npm/_cacache/**",
    "~/.cache/pip/**",
    "/opt/homebrew/**",
    "/usr/local/Cellar/**",
    "/home/linuxbrew/.linuxbrew/**",
    "/tmp/claude-*/**",
    "/private/tmp/claude-*/**",
];

/// The `staging:` section. Absent in policies written before it existed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagingSettings {
    /// Distinct files read outside the project after which a send with a body
    /// carries the atom; absent means [`DEFAULT_OUTSIDE_READS`], `0` turns this
    /// trigger off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outside_reads: Option<u32>,
    /// Distinct folders read outside the project after which a send with a
    /// body carries the atom; absent means [`DEFAULT_OUTSIDE_FOLDERS`], `0`
    /// turns this trigger off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outside_folders: Option<u32>,
    /// Path globs whose reads never count, added to the built-in caches and
    /// temporary folders: sibling repositories a team works across (`~/code/**`).
    /// No `!` exclusions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<String>,
}

impl StagingSettings {
    /// The outside-read threshold under `settings` (the policy's section, if any).
    #[must_use]
    pub fn outside_reads_under(settings: Option<&Self>) -> u32 {
        settings
            .and_then(|s| s.outside_reads)
            .unwrap_or(DEFAULT_OUTSIDE_READS)
    }

    /// The outside-folder threshold under `settings`.
    #[must_use]
    pub fn outside_folders_under(settings: Option<&Self>) -> u32 {
        settings
            .and_then(|s| s.outside_folders)
            .unwrap_or(DEFAULT_OUTSIDE_FOLDERS)
    }
}

/// The built-in ignored paths followed by the ones `settings` adds.
pub(crate) fn ignored(settings: Option<&StagingSettings>) -> impl Iterator<Item = &str> {
    IGNORED.iter().copied().chain(
        settings
            .into_iter()
            .flat_map(|s| s.ignore.iter().map(String::as_str)),
    )
}

/// Each `ignore` entry is a glob that compiles and is not an exclusion, which
/// would make a built-in cache count again. Negative thresholds do not parse.
pub(crate) fn check(settings: Option<&StagingSettings>) -> Result<(), PolicyError> {
    let problem = |problem: String| PolicyError::Rule {
        rule: "staging.ignore".to_owned(),
        problem,
    };
    for p in settings.iter().flat_map(|s| &s.ignore) {
        if p.trim_start().starts_with('!') {
            return Err(problem(format!(
                "`{p}` is an exclusion; the list can only add paths"
            )));
        }
        GlobPattern::compile(p, false).map_err(|e| problem(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{StagingSettings, check};

    #[test]
    fn thresholds_default_and_zero_turns_one_off() {
        assert_eq!(StagingSettings::outside_reads_under(None), 25);
        assert_eq!(StagingSettings::outside_folders_under(None), 2);
        let s = StagingSettings {
            outside_reads: Some(0),
            outside_folders: Some(5),
            ignore: Vec::new(),
        };
        assert_eq!(StagingSettings::outside_reads_under(Some(&s)), 0);
        assert_eq!(StagingSettings::outside_folders_under(Some(&s)), 5);
    }

    #[test]
    fn ignore_takes_globs_but_no_exclusions() {
        let with = |ignore: &[&str]| StagingSettings {
            ignore: ignore.iter().map(|p| (*p).to_owned()).collect(),
            ..StagingSettings::default()
        };
        assert!(check(Some(&with(&["~/code/**"]))).is_ok());
        assert!(check(Some(&with(&["!~/.cargo/registry/**"]))).is_err());
        assert!(check(None).is_ok());
    }
}

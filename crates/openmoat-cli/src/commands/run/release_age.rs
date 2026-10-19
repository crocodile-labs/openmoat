//! The release age `moat run` asks of new package versions (ADR-030): the
//! package managers the agent starts install no version published in the
//! last `sandbox.package_min_release_age_days` days, so a malicious version
//! that the registry takes down within days never reaches the machine.
//!
//! Only the agent's environment changes, never a config file, and only through
//! settings the tools document: npm's `before` (as `npm_config_before`) and
//! uv's `UV_EXCLUDE_NEWER`, both a timestamp. pip, pnpm, Yarn and Bun are not
//! covered. A setting the person made themselves, in the environment or in the
//! project's own files, is left alone, and so is a project with a `uv.lock`:
//! uv records `exclude-newer` in its lockfile, so a cut-off that moves every day
//! would make uv resolve the lockfile again.

use crate::time::day_start_before;

/// npm's `before` setting, read from the environment.
pub const NPM_BEFORE: &str = "npm_config_before";
/// uv's `--exclude-newer`, read from the environment.
pub const UV_EXCLUDE_NEWER: &str = "UV_EXCLUDE_NEWER";

/// Where [`env()`] looks for settings the person made.
pub struct Found<'a> {
    /// Whether `moat run`'s own environment has a variable.
    pub inherited: &'a dyn Fn(&str) -> bool,
    /// Whether the project root has a file.
    pub project_has: &'a dyn Fn(&str) -> bool,
    /// The text of a small configuration file in the project root, if it has one.
    pub project_file: &'a dyn Fn(&str) -> Option<String>,
}

/// The variables to set for the agent. `days` is the policy's release age
/// (`0` is off) and `now_ms` the time.
pub fn env(days: u16, now_ms: i64, found: &Found<'_>) -> Vec<(&'static str, String)> {
    let Found {
        inherited,
        project_has,
        project_file,
    } = found;
    if days == 0 {
        return Vec::new();
    }
    let cutoff = day_start_before(now_ms, days);
    let mut vars = Vec::new();
    // npm reads `npm_config_*` without regard to case
    let npm_set = inherited(NPM_BEFORE)
        || inherited("NPM_CONFIG_BEFORE")
        || project_file(".npmrc").is_some_and(|text| sets_key(&text, "before"));
    if !npm_set {
        vars.push((NPM_BEFORE, cutoff.clone()));
    }
    let uv_set = inherited(UV_EXCLUDE_NEWER)
        || project_has("uv.lock")
        || ["pyproject.toml", "uv.toml"]
            .iter()
            .any(|f| project_file(f).is_some_and(|text| text.contains("exclude-newer")));
    if !uv_set {
        vars.push((UV_EXCLUDE_NEWER, cutoff));
    }
    vars
}

/// Whether an `.npmrc` sets `key` (`before=…`, `before = …`).
fn sets_key(npmrc: &str, key: &str) -> bool {
    npmrc.lines().any(|line| {
        line.trim()
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    })
}

#[cfg(test)]
mod tests;

//! The release age `moat run` requires of new package versions (ADR-030): the
//! package managers the agent starts install no version published in the
//! last `sandbox.package_min_release_age_days` days, so a malicious version
//! that the registry takes down within days never reaches the machine.
//!
//! Only the agent's environment changes, never a config file, and only through
//! settings the tools document: npm's `before` (as `npm_config_before`) and
//! uv's `UV_EXCLUDE_NEWER`, both a timestamp. pip, pnpm, Yarn and Bun are not
//! covered. Both tools read these variables over the project's own files.
//!
//! A cut-off the person set is kept: either variable in `moat run`'s own
//! environment, or the key in their user-level configuration (`~/.npmrc`,
//! `~/.config/uv/uv.toml`). The project's files are the repository's, not the
//! person's: a cut-off there is kept only when it is stricter (an earlier date)
//! than the policy's, so a repository cannot switch the cut-off off with a
//! `before=2099-01-01`. One exception, said on every start: a project with a
//! `uv.lock` gets no `UV_EXCLUDE_NEWER`, since uv records `exclude-newer` in its
//! lockfile and a cut-off that moves every day would make uv resolve it again.

use std::path::PathBuf;

use crate::time::day_start_before;

/// npm's `before` setting, read from the environment.
pub const NPM_BEFORE: &str = "npm_config_before";
/// uv's `--exclude-newer`, read from the environment.
pub const UV_EXCLUDE_NEWER: &str = "UV_EXCLUDE_NEWER";

/// A tool's user-level configuration file, which the person writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserConfig {
    /// npm's `userconfig` (`~/.npmrc`).
    Npm,
    /// uv's user `uv.toml` (`~/.config/uv/uv.toml`).
    Uv,
}

/// Where [`env()`] looks for settings already made.
pub struct Found<'a> {
    /// The value of a variable in `moat run`'s own environment.
    pub inherited: &'a dyn Fn(&str) -> Option<String>,
    /// Whether the project root has a file.
    pub project_has: &'a dyn Fn(&str) -> bool,
    /// The text of a small configuration file in the project root, if it has one.
    pub project_file: &'a dyn Fn(&str) -> Option<String>,
    /// The text of a tool's small user-level configuration file, if there is one.
    pub user_file: &'a dyn Fn(UserConfig) -> Option<String>,
}

/// What `moat run` sets for the agent, and what it says on standard error
/// where it leaves a tool without the cut-off.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReleaseAge {
    /// The variables to set.
    pub vars: Vec<(&'static str, String)>,
    /// One line per tool the project keeps from the cut-off.
    pub notices: Vec<String>,
}

/// The variables to set for the agent. `days` is the policy's release age
/// (`0` is off) and `now_ms` the time.
pub fn env(days: u16, now_ms: i64, found: &Found<'_>) -> ReleaseAge {
    let Found {
        inherited,
        project_has,
        project_file,
        user_file,
    } = found;
    let mut out = ReleaseAge::default();
    if days == 0 {
        return out;
    }
    let cutoff = day_start_before(now_ms, days);
    // npm reads `npm_config_*` without regard to case
    let npm_person = inherited(NPM_BEFORE).is_some()
        || inherited("NPM_CONFIG_BEFORE").is_some()
        || user_file(UserConfig::Npm).is_some_and(|text| npmrc_value(&text, "before").is_some());
    let npm_stricter = project_file(".npmrc")
        .and_then(|text| npmrc_value(&text, "before"))
        .is_some_and(|value| stricter(&value, &cutoff));
    if !npm_person && !npm_stricter {
        out.vars.push((NPM_BEFORE, cutoff.clone()));
    }
    let uv_person = inherited(UV_EXCLUDE_NEWER).is_some()
        || user_file(UserConfig::Uv).is_some_and(|text| uv_value(&text, false).is_some());
    let uv_stricter = [("pyproject.toml", true), ("uv.toml", false)]
        .iter()
        .filter_map(|(file, pyproject)| uv_value(&project_file(file)?, *pyproject))
        .any(|value| stricter(&value, &cutoff));
    if uv_person || uv_stricter {
        return out;
    }
    if project_has("uv.lock") {
        out.notices.push(format!(
            "moat run: uv gets no release-age cut-off ({days} days): the project has a uv.lock, \
             which records the cut-off, so one that moves every day would make uv resolve it \
             again. Set `exclude-newer` under `[tool.uv]` in pyproject.toml, or \
             `{UV_EXCLUDE_NEWER}` before `openmoat run`, to keep one"
        ));
    } else {
        out.vars.push((UV_EXCLUDE_NEWER, cutoff));
    }
    out
}

/// The user-level configuration file of `tool`, as the tool finds it from
/// the environment (`var`) and the home directory `home`: npm's
/// `npm_config_userconfig` or `~/.npmrc`; uv's `$XDG_CONFIG_HOME/uv/uv.toml`
/// or `~/.config/uv/uv.toml`.
pub fn user_config_path(
    tool: UserConfig,
    var: &dyn Fn(&str) -> Option<String>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    let set = |name: &str| var(name).filter(|v| !v.is_empty());
    match tool {
        UserConfig::Npm => set("npm_config_userconfig")
            .or_else(|| set("NPM_CONFIG_USERCONFIG"))
            .map(PathBuf::from)
            .or_else(|| Some(home?.join(".npmrc"))),
        UserConfig::Uv => set("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| Some(home?.join(".config")))
            .map(|config| config.join("uv").join("uv.toml")),
    }
}

/// The value an `.npmrc` gives `key` (`before=…`, `before = …`), the last one
/// winning as npm reads it; comments (`#`, `;`) are not settings.
fn npmrc_value(npmrc: &str, key: &str) -> Option<String> {
    npmrc
        .lines()
        .filter_map(|line| {
            let (name, value) = line.trim().split_once('=')?;
            (name.trim() == key).then(|| value.trim().trim_matches('"').to_owned())
        })
        .next_back()
}

/// The `exclude-newer` a uv configuration sets: under `[tool.uv]` in a
/// `pyproject.toml`, at the top of a `uv.toml`. Parsed as TOML, so a comment
/// or another key that mentions it does not count; text that is not TOML sets
/// nothing.
fn uv_value(text: &str, pyproject: bool) -> Option<String> {
    let doc: toml_edit::DocumentMut = text.parse().ok()?;
    let table = doc.as_table();
    let table = if pyproject {
        table
            .get("tool")?
            .as_table_like()?
            .get("uv")?
            .as_table_like()?
    } else {
        table
    };
    let value = table.get("exclude-newer")?.as_str()?;
    Some(value.to_owned())
}

/// Whether a cut-off `value` (`2026-01-01`, `2026-01-01T00:00:00Z`) lies on a
/// day before `cutoff`'s, so it lets fewer versions in. A value that is not a
/// date (`1 week`, `2099`, garbage) is not stricter: the policy's cut-off applies.
fn stricter(value: &str, cutoff: &str) -> bool {
    let date = |text: &str| -> Option<String> {
        let day = text.trim().get(..10)?;
        let shape = day.char_indices().all(|(i, c)| match i {
            4 | 7 => c == '-',
            _ => c.is_ascii_digit(),
        });
        shape.then(|| day.to_owned())
    };
    matches!((date(value), date(cutoff)), (Some(v), Some(c)) if v < c)
}

#[cfg(test)]
mod tests;

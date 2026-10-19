//! Where OpenClaw keeps its state and its configuration
//! (<https://docs.openclaw.ai/help/environment>):
//!
//! - `OPENCLAW_HOME` replaces the home directory in OpenClaw's defaults;
//! - `OPENCLAW_STATE_DIR` names the state directory, `~/.openclaw` by default;
//! - `OPENCLAW_CONFIG_PATH` names the configuration file, `openclaw.json` in the
//!   state directory by default.
//!
//! Each may start with `~`: the OS home directory in `OPENCLAW_HOME`, that home
//! in the other two (OpenClaw's `resolveUserPath` with its `OPENCLAW_HOME`
//! aware home). A blank value, `undefined` or `null` counts as unset. An explicit
//! state directory or configuration path wins over what `OPENCLAW_HOME` implies.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::home::user_home;

/// The variables, in the order they are resolved.
pub const VARIABLES: [&str; 3] = [
    "OPENCLAW_HOME",
    "OPENCLAW_STATE_DIR",
    "OPENCLAW_CONFIG_PATH",
];
/// The state directory's name in the home directory.
pub const STATE_DIR_NAME: &str = ".openclaw";
/// The configuration file's name in the state directory.
pub const CONFIG_FILE: &str = "openclaw.json";

/// One OpenClaw installation's state directory and configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub state_dir: PathBuf,
    pub config: PathBuf,
}

impl Location {
    /// `state_dir` with its configuration in it, or at `config` when that is
    /// recorded elsewhere.
    pub fn at(state_dir: PathBuf, config: Option<PathBuf>) -> Self {
        let config = config.unwrap_or_else(|| state_dir.join(CONFIG_FILE));
        Self { state_dir, config }
    }

    /// OpenClaw's default: `~/.openclaw/openclaw.json`.
    pub fn default_for(home: &Path) -> Self {
        Self::at(home.join(STATE_DIR_NAME), None)
    }

    /// Whether the configuration is the default file of the state directory.
    pub fn config_is_default(&self) -> bool {
        self.config == self.state_dir.join(CONFIG_FILE)
    }

    /// The location this shell's environment names, when it sets one of
    /// [`VARIABLES`].
    pub fn from_env() -> Result<Option<Self>> {
        let get = |name: &str| std::env::var(name).ok();
        if !VARIABLES.iter().any(|name| value(get(name)).is_some()) {
            return Ok(None);
        }
        resolve(get, &user_home()?).map(Some)
    }
}

/// What `moat doctor` says when this shell's environment names another
/// OpenClaw than `set_up`, the one `moat init` recorded; `None` when it agrees
/// or names none.
pub fn env_disagrees(set_up: &Location) -> Result<Option<String>> {
    Ok(Location::from_env()?
        .filter(|env| env != set_up)
        .map(|env| {
            format!(
                "OPENCLAW_HOME, OPENCLAW_STATE_DIR or OPENCLAW_CONFIG_PATH name {} (state {}), \
                 but `moat init` set up {} (state {}), which moat uses; run `moat init` with \
                 them set to set up that one instead",
                env.config.display(),
                env.state_dir.display(),
                set_up.config.display(),
                set_up.state_dir.display()
            )
        }))
}

/// The location `get` (a variable's value) names, with `os_home` the home
/// directory the OS reports.
pub fn resolve(get: impl Fn(&str) -> Option<String>, os_home: &Path) -> Result<Location> {
    let [home_var, state_var, config_var] = VARIABLES;
    let home = match value(get(home_var)) {
        Some(home) => expand(&home, os_home)?,
        None => os_home.to_path_buf(),
    };
    let state_dir = match value(get(state_var)) {
        Some(state) => expand(&state, &home)?,
        None => home.join(STATE_DIR_NAME),
    };
    let config = match value(get(config_var)) {
        Some(config) => Some(expand(&config, &home)?),
        None => None,
    };
    Ok(Location::at(state_dir, config))
}

/// A variable's value as OpenClaw reads it: trimmed, and unset when blank,
/// `undefined` or `null`.
fn value(raw: Option<String>) -> Option<String> {
    raw.map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty() && v != "undefined" && v != "null")
}

/// `path` with a leading `~` as `home`, made absolute.
fn expand(path: &str, home: &Path) -> Result<PathBuf> {
    let expanded = match path.strip_prefix('~') {
        Some("") => home.to_path_buf(),
        Some(rest) if rest.starts_with(['/', '\\']) => home.join(&rest[1..]),
        _ => PathBuf::from(path),
    };
    crate::context::absolute(&expanded)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn located(vars: &[(&str, &str)]) -> Location {
        let vars: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        resolve(|name| vars.get(name).cloned(), Path::new("/os/home")).unwrap()
    }

    /// A path a variable names, made absolute as `expand` does: on Windows
    /// `/srv` gets the current drive.
    fn abs(path: &str) -> PathBuf {
        crate::context::absolute(Path::new(path)).unwrap()
    }

    #[test]
    fn defaults_follow_openclaw_home_and_explicit_paths_win() {
        assert_eq!(located(&[]), Location::default_for(Path::new("/os/home")));
        let home = located(&[("OPENCLAW_HOME", "~/svc")]);
        assert_eq!(home.state_dir, abs("/os/home/svc/.openclaw"));
        assert_eq!(home.config, abs("/os/home/svc/.openclaw/openclaw.json"));
        assert!(home.config_is_default());
        let state = located(&[
            ("OPENCLAW_HOME", "/srv/oc"),
            ("OPENCLAW_STATE_DIR", "~/state"),
        ]);
        assert_eq!(state.state_dir, abs("/srv/oc/state"));
        assert_eq!(state.config, abs("/srv/oc/state/openclaw.json"));
        let config = located(&[("OPENCLAW_CONFIG_PATH", " /etc/oc/main.json5 ")]);
        assert_eq!(config.state_dir, PathBuf::from("/os/home/.openclaw"));
        assert_eq!(config.config, abs("/etc/oc/main.json5"));
        assert!(!config.config_is_default());
    }

    #[test]
    fn blank_undefined_and_null_are_unset() {
        for unset in ["", "  ", "undefined", "null"] {
            assert_eq!(
                located(&[("OPENCLAW_HOME", unset), ("OPENCLAW_CONFIG_PATH", unset)]),
                Location::default_for(Path::new("/os/home")),
                "{unset:?}"
            );
        }
    }
}

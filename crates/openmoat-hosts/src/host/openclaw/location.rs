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
//!
//! Also the form of `openclaw.json` the lock pins ([`pinned_form`]).

use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{CONFIG_FILE, PLUGIN_ID, STATE_DIR_NAME, STATE_DIR_VARIABLE};
use crate::contract::{Locate, Located};

/// The variables, in the order they are resolved.
const VARIABLES: [&str; 3] = ["OPENCLAW_HOME", STATE_DIR_VARIABLE, "OPENCLAW_CONFIG_PATH"];

/// OpenClaw's location rules.
pub(super) struct OpenClaw;

pub(super) static LOCATE: OpenClaw = OpenClaw;

impl Locate for OpenClaw {
    fn variables(&self) -> &'static [&'static str] {
        &VARIABLES
    }

    fn moved(&self, get: &dyn Fn(&str) -> Option<String>) -> bool {
        VARIABLES.iter().any(|name| value(get(name)).is_some())
    }

    fn resolve(
        &self,
        get: &dyn Fn(&str) -> Option<String>,
        os_home: &Path,
        absolute: &dyn Fn(&Path) -> io::Result<PathBuf>,
    ) -> io::Result<Located> {
        let [home_var, state_var, config_var] = VARIABLES;
        let home = match value(get(home_var)) {
            Some(home) => expand(&home, os_home, absolute)?,
            None => os_home.to_path_buf(),
        };
        let state_dir = match value(get(state_var)) {
            Some(state) => expand(&state, &home, absolute)?,
            None => home.join(STATE_DIR_NAME),
        };
        let config = match value(get(config_var)) {
            Some(config) => Some(expand(&config, &home, absolute)?),
            None => None,
        };
        Ok(self.at(state_dir, config))
    }

    fn at(&self, dir: PathBuf, config: Option<PathBuf>) -> Located {
        let config = config.unwrap_or_else(|| dir.join(CONFIG_FILE));
        Located { dir, config }
    }

    fn default_for(&self, home: &Path) -> Located {
        self.at(home.join(STATE_DIR_NAME), None)
    }
}

/// A variable's value as OpenClaw reads it: trimmed, and unset when blank,
/// `undefined` or `null`.
fn value(raw: Option<String>) -> Option<String> {
    raw.map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty() && v != "undefined" && v != "null")
}

/// `path` with a leading `~` as `home`, made absolute.
fn expand(
    path: &str,
    home: &Path,
    absolute: &dyn Fn(&Path) -> io::Result<PathBuf>,
) -> io::Result<PathBuf> {
    let expanded = match path.strip_prefix('~') {
        Some("") => home.to_path_buf(),
        Some(rest) if rest.starts_with(['/', '\\']) => home.join(&rest[1..]),
        _ => PathBuf::from(path),
    };
    absolute(&expanded)
}

/// An OpenClaw configuration that loads OpenMoat's plugin
/// (`plugins.entries.openmoat`) without `mcp.servers`; `None` for any other
/// file. The MCP pins (ADR-026) hold each server's definition, so a changed
/// server holds back only its own tools; every other change, and one that
/// removes OpenMoat's entry, is drift.
pub(super) fn pinned_form(mut value: Value) -> Option<Value> {
    value.pointer(&format!("/plugins/entries/{PLUGIN_ID}"))?;
    let top = value.as_object_mut()?;
    if let Some(mcp) = top.get_mut("mcp").and_then(Value::as_object_mut) {
        mcp.remove("servers");
        // The first server added brings `mcp` with it.
        if mcp.is_empty() {
            top.remove("mcp");
        }
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn located(vars: &[(&str, &str)]) -> Located {
        let vars: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        LOCATE
            .resolve(
                &|name| vars.get(name).cloned(),
                Path::new("/os/home"),
                &|path: &Path| std::path::absolute(path),
            )
            .unwrap()
    }

    /// A path a variable names, made absolute as `expand` does: on Windows
    /// `/srv` gets the current drive.
    fn abs(path: &str) -> PathBuf {
        std::path::absolute(path).unwrap()
    }

    #[test]
    fn defaults_follow_openclaw_home_and_explicit_paths_win() {
        assert_eq!(located(&[]), LOCATE.default_for(Path::new("/os/home")));
        let home = located(&[("OPENCLAW_HOME", "~/svc")]);
        assert_eq!(home.dir, abs("/os/home/svc/.openclaw"));
        assert_eq!(home.config, abs("/os/home/svc/.openclaw/openclaw.json"));
        assert!(LOCATE.config_is_default(&home));
        let state = located(&[
            ("OPENCLAW_HOME", "/srv/oc"),
            ("OPENCLAW_STATE_DIR", "~/state"),
        ]);
        assert_eq!(state.dir, abs("/srv/oc/state"));
        assert_eq!(state.config, abs("/srv/oc/state/openclaw.json"));
        let config = located(&[("OPENCLAW_CONFIG_PATH", " /etc/oc/main.json5 ")]);
        assert_eq!(config.dir, PathBuf::from("/os/home/.openclaw"));
        assert_eq!(config.config, abs("/etc/oc/main.json5"));
        assert!(!LOCATE.config_is_default(&config));
    }

    #[test]
    fn blank_undefined_and_null_are_unset() {
        for unset in ["", "  ", "undefined", "null"] {
            assert!(!LOCATE.moved(&|_| Some(unset.to_owned())), "{unset:?}");
            assert_eq!(
                located(&[("OPENCLAW_HOME", unset), ("OPENCLAW_CONFIG_PATH", unset)]),
                LOCATE.default_for(Path::new("/os/home")),
                "{unset:?}"
            );
        }
    }
}

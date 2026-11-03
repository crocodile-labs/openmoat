//! Where goose keeps its configuration and its plugins (`config/paths.rs`,
//! v1.57.0, with the `etcetera` crate's app strategy):
//!
//! - `GOOSE_PATH_ROOT`, when it is an absolute path, holds both: the
//!   configuration in `<root>/config`, the plugins in `<root>/.agents/plugins`;
//! - otherwise the configuration is `$XDG_CONFIG_HOME/goose` (an absolute
//!   value only), else `~/.config/goose`, and on Windows
//!   `~\AppData\Roaming\Block\goose\config`; the plugins are
//!   `~/.agents/plugins` on every platform.
//!
//! The configuration directory is how OpenMoat tells goose is installed (goose
//! writes `config.yaml` there on its first start); OpenMoat's hook file is its
//! plugin's `hooks/hooks.json` in the plugins directory, which is shared with
//! other agents that read Open Plugins and so says nothing about goose.

use std::io;
use std::path::{Path, PathBuf};

use crate::contract::{Locate, Located};

/// The variable that moves goose's configuration and plugins together.
pub(super) const ROOT_VARIABLE: &str = "GOOSE_PATH_ROOT";
/// The configuration directory under the home directory, outside Windows.
pub(super) const DIR_NAME: &str = ".config/goose";
/// The hook file's name, in OpenMoat's plugin's `hooks` directory.
pub(super) const HOOK_FILE_NAME: &str = "hooks.json";
/// The variable that names the base of the configuration directory.
const XDG: &str = "XDG_CONFIG_HOME";
/// The configuration directory under the home directory on Windows.
const WINDOWS_DIR: [&str; 5] = ["AppData", "Roaming", "Block", "goose", "config"];

/// OpenMoat's hook file under a directory that holds `.agents`.
fn hook_file_in(home: &Path) -> PathBuf {
    home.join(".agents")
        .join("plugins")
        .join("openmoat")
        .join("hooks")
        .join(HOOK_FILE_NAME)
}

/// goose's location rules.
pub(super) struct Goose;

pub(super) static LOCATE: Goose = Goose;

impl Locate for Goose {
    fn variables(&self) -> &'static [&'static str] {
        if cfg!(windows) {
            &[ROOT_VARIABLE]
        } else {
            &[ROOT_VARIABLE, XDG]
        }
    }

    fn moved(&self, get: &dyn Fn(&str) -> Option<String>) -> bool {
        self.variables()
            .iter()
            .any(|name| absolute_value(get(name)).is_some())
    }

    fn resolve(
        &self,
        get: &dyn Fn(&str) -> Option<String>,
        os_home: &Path,
        absolute: &dyn Fn(&Path) -> io::Result<PathBuf>,
    ) -> io::Result<Located> {
        if let Some(root) = absolute_value(get(ROOT_VARIABLE)) {
            let root = absolute(&root)?;
            return Ok(Located {
                dir: root.join("config"),
                config: hook_file_in(&root),
            });
        }
        let dir = match absolute_value(get(XDG)).filter(|_| !cfg!(windows)) {
            Some(base) => absolute(&base)?.join("goose"),
            None => self.default_for(os_home).dir,
        };
        Ok(Located {
            dir,
            config: absolute(&hook_file_in(os_home))?,
        })
    }

    /// The hook file is not in `dir`: it is found from the home directory the
    /// default configuration directory is in, or from a `GOOSE_PATH_ROOT`
    /// whose `config` `dir` is. A configuration directory moved by
    /// `XDG_CONFIG_HOME` says nothing about the home, so its hook file comes
    /// from the record `moat init` keeps.
    fn at(&self, dir: PathBuf, config: Option<PathBuf>) -> Located {
        let config = config.unwrap_or_else(|| {
            let home = home_of(&dir).unwrap_or_else(|| dir.parent().unwrap_or(&dir).to_path_buf());
            hook_file_in(&home)
        });
        Located { dir, config }
    }

    fn default_for(&self, home: &Path) -> Located {
        let dir = if cfg!(windows) {
            WINDOWS_DIR.iter().fold(home.to_path_buf(), |p, part| p.join(part))
        } else {
            home.join(DIR_NAME)
        };
        Located {
            dir,
            config: hook_file_in(home),
        }
    }

    /// `XDG_CONFIG_HOME` is read by many programs.
    fn variables_are_the_hosts(&self) -> bool {
        false
    }
}

/// The home directory a default configuration directory is in.
fn home_of(dir: &Path) -> Option<PathBuf> {
    let parts: &[&str] = if cfg!(windows) {
        &WINDOWS_DIR
    } else {
        &[".config", "goose"]
    };
    let mut at = dir;
    for part in parts.iter().rev() {
        if at.file_name()? != *part {
            return None;
        }
        at = at.parent()?;
    }
    Some(at.to_path_buf())
}

/// A variable's value, when it is an absolute path (goose ignores any other).
fn absolute_value(raw: Option<String>) -> Option<PathBuf> {
    raw.map(PathBuf::from).filter(|p| p.is_absolute())
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

    fn abs(p: &str) -> PathBuf {
        std::path::absolute(p).unwrap()
    }

    #[test]
    fn the_root_moves_configuration_and_plugins_together() {
        if cfg!(windows) {
            return;
        }
        let moved = located(&[("GOOSE_PATH_ROOT", "/srv/g"), ("XDG_CONFIG_HOME", "/x")]);
        assert_eq!(moved.dir, abs("/srv/g/config"));
        assert_eq!(
            moved.config,
            abs("/srv/g/.agents/plugins/openmoat/hooks/hooks.json")
        );
        assert!(LOCATE.config_is_default(&moved));
        // A relative root is ignored, as goose ignores it.
        assert_eq!(located(&[("GOOSE_PATH_ROOT", "rel")]), located(&[]));
        assert!(!LOCATE.moved(&|_| Some("rel".to_owned())));
    }

    #[test]
    fn the_default_and_the_xdg_directory_keep_the_plugins_at_home() {
        if cfg!(windows) {
            return;
        }
        let default = located(&[]);
        assert_eq!(default, LOCATE.default_for(Path::new("/os/home")));
        assert_eq!(default.dir, PathBuf::from("/os/home/.config/goose"));
        assert!(LOCATE.config_is_default(&default));
        let xdg = located(&[("XDG_CONFIG_HOME", "/x")]);
        assert_eq!(xdg.dir, abs("/x/goose"));
        assert_eq!(xdg.config, default.config);
        // The record keeps the hook file of a directory XDG moved.
        assert_eq!(LOCATE.at(xdg.dir.clone(), Some(xdg.config.clone())), xdg);
    }
}

//! Where OpenCode keeps the configuration directory whose plugins it loads:
//! `OPENCODE_CONFIG_DIR` when it is set, else `$XDG_CONFIG_HOME/opencode`,
//! else `~/.config/opencode`. The same rule on Windows, where the default is
//! `%USERPROFILE%\.config\opencode`.
//!
//! OpenCode 2 takes `OPENCODE_CONFIG_DIR` as its global directory in place of
//! the XDG one (2.2.0 `util/src/global.ts:79`, `cli/src/server-process.ts:39`);
//! OpenCode 1 reads it in addition to the XDG one (`config/paths.ts`,
//! `directories`). A plugin there is loaded by both, so `moat init` installs
//! there when it is set; the XDG directory, which OpenCode 1 still reads, is
//! then a further directory (`InstallSpec::also_dirs`). The XDG directory comes
//! from `xdg-basedir`, which takes an empty `XDG_CONFIG_HOME` as unset and
//! expands no `~` (1.x `packages/core/src/global.ts`; 2.x
//! `util/src/global-roots.ts`).
//!
//! `XDG_CONFIG_HOME` is read by many programs, so a value of it says nothing
//! about whether OpenCode is installed ([`Locate::variables_are_the_hosts`]).

use std::io;
use std::path::{Path, PathBuf};

use crate::contract::{Locate, Located};

/// The variable that names the base of OpenCode's XDG configuration directory.
pub(super) const VARIABLE: &str = "XDG_CONFIG_HOME";
/// The variable that names the directory OpenCode 2 reads in its place.
pub(super) const CONFIG_DIR: &str = "OPENCODE_CONFIG_DIR";
/// The configuration directory's path under the home directory by default.
pub(super) const DIR_NAME: &str = ".config/opencode";
/// The directory's name under `XDG_CONFIG_HOME`.
pub(super) const APP: &str = "opencode";

const VARIABLES: [&str; 2] = [VARIABLE, CONFIG_DIR];

/// OpenCode's location rules.
pub(super) struct OpenCode;

pub(super) static LOCATE: OpenCode = OpenCode;

impl Locate for OpenCode {
    fn variables(&self) -> &'static [&'static str] {
        &VARIABLES
    }

    fn moved(&self, get: &dyn Fn(&str) -> Option<String>) -> bool {
        VARIABLES
            .iter()
            .any(|name| get(name).is_some_and(|v| !v.is_empty()))
    }

    fn resolve(
        &self,
        get: &dyn Fn(&str) -> Option<String>,
        os_home: &Path,
        absolute: &dyn Fn(&Path) -> io::Result<PathBuf>,
    ) -> io::Result<Located> {
        let set = |name: &str| get(name).filter(|v| !v.is_empty());
        let dir = match (set(CONFIG_DIR), set(VARIABLE)) {
            (Some(dir), _) => absolute(Path::new(&dir))?,
            (None, Some(base)) => absolute(&Path::new(&base).join(APP))?,
            (None, None) => os_home.join(DIR_NAME),
        };
        Ok(self.at(dir, None))
    }

    fn at(&self, dir: PathBuf, config: Option<PathBuf>) -> Located {
        let config = config.unwrap_or_else(|| dir.join(super::PLUGIN_FILE));
        Located { dir, config }
    }

    fn default_for(&self, home: &Path) -> Located {
        self.at(home.join(DIR_NAME), None)
    }

    fn variables_are_the_hosts(&self) -> bool {
        false
    }
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

    #[test]
    fn the_directory_is_under_xdg_config_home_or_the_home() {
        let default = located(&[]);
        assert_eq!(default, LOCATE.default_for(Path::new("/os/home")));
        assert_eq!(default.dir, PathBuf::from("/os/home/.config/opencode"));
        assert_eq!(
            default.config,
            PathBuf::from("/os/home/.config/opencode/plugins/openmoat.js")
        );
        let moved = located(&[("XDG_CONFIG_HOME", "/srv/cfg")]);
        assert_eq!(moved.dir, std::path::absolute("/srv/cfg/opencode").unwrap());
        assert!(LOCATE.config_is_default(&moved));
        // An empty value is unset, as `xdg-basedir` reads it.
        assert!(!LOCATE.moved(&|_| Some(String::new())));
        assert_eq!(located(&[("XDG_CONFIG_HOME", "")]), default);
        assert!(!LOCATE.variables_are_the_hosts());
    }

    /// OpenCode 2 loads global plugins from `OPENCODE_CONFIG_DIR` in place of
    /// the XDG directory, and OpenCode 1 loads them from it too.
    #[test]
    fn opencode_config_dir_is_where_both_versions_load_the_plugin() {
        let both = located(&[("XDG_CONFIG_HOME", "/srv/cfg"), ("OPENCODE_CONFIG_DIR", "/occ")]);
        assert_eq!(both.dir, std::path::absolute("/occ").unwrap());
        assert_eq!(
            both.config,
            std::path::absolute("/occ/plugins/openmoat.js").unwrap()
        );
        assert!(LOCATE.moved(&|name| (name == "OPENCODE_CONFIG_DIR").then(|| "/occ".to_owned())));
        assert_eq!(located(&[("OPENCODE_CONFIG_DIR", "")]), located(&[]));
    }
}

//! Where OpenCode keeps its configuration: `$XDG_CONFIG_HOME/opencode`, else
//! `~/.config/opencode` (`packages/core/src/global.ts`, through `xdg-basedir`,
//! which takes an empty `XDG_CONFIG_HOME` as unset and expands no `~`). The
//! same rule on Windows, where the default is `%USERPROFILE%\.config\opencode`.
//!
//! `XDG_CONFIG_HOME` is read by many programs, so a value of it says nothing
//! about whether OpenCode is installed ([`Locate::variables_are_the_hosts`]).
//! `OPENCODE_CONFIG_DIR` names a further directory OpenCode reads; it does not
//! move this one, whose plugins OpenCode always loads (`config/paths.ts`).

use std::io;
use std::path::{Path, PathBuf};

use crate::contract::{Locate, Located};

/// The variable that names the base of OpenCode's configuration directory.
pub(super) const VARIABLE: &str = "XDG_CONFIG_HOME";
/// The configuration directory's path under the home directory by default.
pub(super) const DIR_NAME: &str = ".config/opencode";
/// The directory's name under `XDG_CONFIG_HOME`.
const APP: &str = "opencode";

const VARIABLES: [&str; 1] = [VARIABLE];

/// OpenCode's location rules.
pub(super) struct OpenCode;

pub(super) static LOCATE: OpenCode = OpenCode;

impl Locate for OpenCode {
    fn variables(&self) -> &'static [&'static str] {
        &VARIABLES
    }

    fn moved(&self, get: &dyn Fn(&str) -> Option<String>) -> bool {
        get(VARIABLE).is_some_and(|v| !v.is_empty())
    }

    fn resolve(
        &self,
        get: &dyn Fn(&str) -> Option<String>,
        os_home: &Path,
        absolute: &dyn Fn(&Path) -> io::Result<PathBuf>,
    ) -> io::Result<Located> {
        let dir = match get(VARIABLE).filter(|v| !v.is_empty()) {
            Some(base) => absolute(&Path::new(&base).join(APP))?,
            None => os_home.join(DIR_NAME),
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
}

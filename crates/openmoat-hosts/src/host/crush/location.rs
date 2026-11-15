//! Where Crush keeps the global `crush.json` OpenMoat's hook goes into:
//! `$CRUSH_GLOBAL_CONFIG/crush.json` when the variable is set, else
//! `$XDG_CONFIG_HOME/crush/crush.json`, else `~/.config/crush/crush.json`
//! (`GlobalConfig()` in `internal/config/load.go`, `Config()` in
//! `internal/home/home.go`). The same rule on Windows was not checked.

use crate::contract::XdgDir;

/// The variable that names the directory of the global `crush.json` itself.
const CONFIG_DIR: &str = "CRUSH_GLOBAL_CONFIG";
/// The variable `moat init` records as moving the directory.
pub(super) const VARIABLE: &str = XdgDir::BASE;
/// The configuration directory's path under the home directory by default.
pub(super) const DIR_NAME: &str = ".config/crush";
/// The global configuration file, which holds OpenMoat's hook.
pub(super) const CONFIG_FILE: &str = "crush.json";

pub(super) static LOCATE: XdgDir = XdgDir {
    own: CONFIG_DIR,
    variables: &[XdgDir::BASE, CONFIG_DIR],
    app: "crush",
    dir_name: DIR_NAME,
    file: CONFIG_FILE,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::contract::{Locate, Located};

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
    fn the_file_is_under_the_global_config_variable_xdg_or_the_home() {
        let default = located(&[]);
        assert_eq!(default, LOCATE.default_for(Path::new("/os/home")));
        assert_eq!(
            default.config,
            PathBuf::from("/os/home/.config/crush/crush.json")
        );
        let xdg = located(&[("XDG_CONFIG_HOME", "/srv/cfg")]);
        assert_eq!(xdg.dir, std::path::absolute("/srv/cfg/crush").unwrap());
        assert!(LOCATE.config_is_default(&xdg));
        let both = located(&[("XDG_CONFIG_HOME", "/srv/cfg"), ("CRUSH_GLOBAL_CONFIG", "/cg")]);
        assert_eq!(both.config, std::path::absolute("/cg/crush.json").unwrap());
        assert!(LOCATE.moved(&|name| (name == "CRUSH_GLOBAL_CONFIG").then(|| "/cg".to_owned())));
        assert_eq!(located(&[("CRUSH_GLOBAL_CONFIG", "")]), default);
        assert!(!LOCATE.variables_are_the_hosts());
    }
}

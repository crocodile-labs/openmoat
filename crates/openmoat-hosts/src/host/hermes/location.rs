//! Where Hermes Agent keeps its home (`hermes_constants.py`, v0.22.5):
//!
//! - `HERMES_HOME` names it, after `~` and environment variables in it are
//!   expanded; a blank value counts as unset;
//! - otherwise `~/.hermes`, and on Windows `%LOCALAPPDATA%\hermes`
//!   (`~\AppData\Local\hermes` without `LOCALAPPDATA`);
//! - `HERMES_DATA_DIR_SUFFIX` is appended to the default's name.
//!
//! A profile is a home of its own under `profiles/<name>/`, chosen with
//! `hermes -p <name>`, the sticky `active_profile` file or a `HERMES_HOME`
//! that names it; `moat init` sets up the one home this environment names,
//! and a person who uses another profile runs it with `HERMES_HOME` naming
//! that profile.

use std::io;
use std::path::{Path, PathBuf};

use super::CONFIG_FILE;
use crate::contract::{Locate, Located};

/// The variable that names the Hermes home.
pub(super) const HOME_VARIABLE: &str = "HERMES_HOME";
/// The home's name in the home directory, on every platform but Windows.
pub(super) const DIR_NAME: &str = ".hermes";
/// The variable whose value Hermes appends to the default home's name.
const SUFFIX_VARIABLE: &str = "HERMES_DATA_DIR_SUFFIX";
/// Windows's per-user application data, which holds the default home there.
const LOCAL_APP_DATA: &str = "LOCALAPPDATA";

/// The variables, in the order they are resolved.
const VARIABLES: [&str; 3] = [HOME_VARIABLE, SUFFIX_VARIABLE, LOCAL_APP_DATA];

/// Hermes Agent's location rules.
pub(super) struct Hermes;

pub(super) static LOCATE: Hermes = Hermes;

impl Locate for Hermes {
    fn variables(&self) -> &'static [&'static str] {
        if cfg!(windows) {
            &VARIABLES
        } else {
            &VARIABLES[..2]
        }
    }

    fn moved(&self, get: &dyn Fn(&str) -> Option<String>) -> bool {
        self.variables()
            .iter()
            .any(|name| value(get(name)).is_some())
    }

    fn resolve(
        &self,
        get: &dyn Fn(&str) -> Option<String>,
        os_home: &Path,
        absolute: &dyn Fn(&Path) -> io::Result<PathBuf>,
    ) -> io::Result<Located> {
        if let Some(home) = value(get(HOME_VARIABLE)) {
            return Ok(self.at(absolute(&expand(&home, get, os_home))?, None));
        }
        let suffix = get(SUFFIX_VARIABLE).unwrap_or_default();
        let dir = if cfg!(windows) {
            let base = value(get(LOCAL_APP_DATA))
                .map_or_else(|| os_home.join("AppData").join("Local"), PathBuf::from);
            base.join(format!("hermes{suffix}"))
        } else {
            os_home.join(format!("{DIR_NAME}{suffix}"))
        };
        Ok(self.at(absolute(&dir)?, None))
    }

    fn at(&self, dir: PathBuf, config: Option<PathBuf>) -> Located {
        let config = config.unwrap_or_else(|| dir.join(CONFIG_FILE));
        Located { dir, config }
    }

    fn default_for(&self, home: &Path) -> Located {
        let dir = if cfg!(windows) {
            home.join("AppData").join("Local").join("hermes")
        } else {
            home.join(DIR_NAME)
        };
        self.at(dir, None)
    }
}

/// A variable's value as Hermes reads it: trimmed, and unset when blank.
fn value(raw: Option<String>) -> Option<String> {
    raw.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

/// `path` with environment variables (`$NAME`, `${NAME}`, and `%NAME%` on
/// Windows) and a leading `~` expanded, as Python's `os.path.expandvars` and
/// `expanduser` do: a variable that is not set stays as written.
fn expand(path: &str, get: &dyn Fn(&str) -> Option<String>, home: &Path) -> PathBuf {
    let path = expand_vars(path, get);
    match path.strip_prefix('~') {
        Some("") => home.to_path_buf(),
        Some(rest) if rest.starts_with(['/', '\\']) => home.join(&rest[1..]),
        _ => PathBuf::from(path),
    }
}

fn expand_vars(path: &str, get: &dyn Fn(&str) -> Option<String>) -> String {
    let name_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(at) = rest.find(['$', '%']) {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let (name, used) = if let Some(braced) = tail.strip_prefix("${") {
            match braced.find('}') {
                Some(end) => (&braced[..end], end + 3),
                None => ("", 0),
            }
        } else if let Some(bare) = tail.strip_prefix('$') {
            let end = bare.find(|c| !name_char(c)).unwrap_or(bare.len());
            (&bare[..end], end + 1)
        } else if cfg!(windows) {
            let percent = &tail[1..];
            match percent.find('%') {
                Some(end) if end > 0 && percent[..end].chars().all(name_char) => {
                    (&percent[..end], end + 2)
                }
                _ => ("", 0),
            }
        } else {
            ("", 0)
        };
        if let Some(value) = get(name).filter(|_| !name.is_empty() && used > 0) {
            out.push_str(&value);
            rest = &tail[used..];
        } else {
            out.push_str(&tail[..1]);
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
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
    fn hermes_home_wins_and_is_expanded() {
        let abs = |p: &str| std::path::absolute(p).unwrap();
        let home = located(&[("HERMES_HOME", " ~/svc/hermes ")]);
        assert_eq!(home.dir, abs("/os/home/svc/hermes"));
        assert_eq!(home.config, abs("/os/home/svc/hermes/config.yaml"));
        let vars = located(&[("HERMES_HOME", "${ROOT}/h/$P"), ("ROOT", "/srv"), ("P", "x")]);
        assert_eq!(vars.dir, abs("/srv/h/x"));
        let unset = located(&[("HERMES_HOME", "/srv/$NOPE")]);
        assert_eq!(unset.dir, abs("/srv/$NOPE"));
    }

    #[test]
    fn blank_is_unset_and_the_default_takes_the_suffix() {
        assert!(!LOCATE.moved(&|name| (name == "HERMES_HOME").then(|| "  ".to_owned())));
        let suffixed = located(&[("HERMES_DATA_DIR_SUFFIX", "-dev")]);
        if cfg!(windows) {
            assert!(suffixed.dir.ends_with("AppData/Local/hermes-dev"));
        } else {
            assert_eq!(suffixed.dir, PathBuf::from("/os/home/.hermes-dev"));
            assert_eq!(located(&[]), LOCATE.default_for(Path::new("/os/home")));
        }
    }
}

//! Where a host keeps the configuration `moat init` writes its hook into
//! ([`InstallSpec::location`](super::InstallSpec::location)), and the form of
//! its hook file the lock pins
//! ([`InstallSpec::pinned_form`](super::InstallSpec::pinned_form)).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// How the CLI finds a host's configuration directory and hook file.
#[derive(Clone, Copy)]
pub enum Location {
    /// One directory, which [`dir_variable`](super::InstallSpec::dir_variable)
    /// moves (or the home directory it is in: `variable_names_home`), holds
    /// [`config_file`](super::InstallSpec::config_file).
    OneDir,
    /// The host's own rules, when several variables say where the
    /// directory and the file are (OpenClaw).
    Custom(&'static dyn Locate),
}

impl fmt::Debug for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OneDir => f.write_str("OneDir"),
            Self::Custom(_) => f.write_str("Custom"),
        }
    }
}

/// One installation's configuration directory, the one `hosts.json` records,
/// and its hook file, which may be elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The configuration directory.
    pub dir: PathBuf,
    /// The hook file.
    pub config: PathBuf,
}

/// A host's own rules for where its configuration is. Pure: the CLI passes
/// the environment's variables, the home directory and how to make a path
/// absolute.
pub trait Locate: Sync {
    /// The variables that move the configuration, in the order they are
    /// resolved.
    fn variables(&self) -> &'static [&'static str];

    /// Whether `get` (a variable's value) sets any of [`Self::variables`].
    fn moved(&self, get: &dyn Fn(&str) -> Option<String>) -> bool;

    /// The location `get` names, with `os_home` the home directory the OS
    /// reports and `absolute` how a path a variable names is made absolute.
    fn resolve(
        &self,
        get: &dyn Fn(&str) -> Option<String>,
        os_home: &Path,
        absolute: &dyn Fn(&Path) -> io::Result<PathBuf>,
    ) -> io::Result<Located>;

    /// `dir` with the hook file in it, or at `config` when that is recorded
    /// elsewhere.
    fn at(&self, dir: PathBuf, config: Option<PathBuf>) -> Located;

    /// The host's default location under `home`.
    fn default_for(&self, home: &Path) -> Located;

    /// Whether `located`'s hook file is the default one of its directory.
    fn config_is_default(&self, located: &Located) -> bool {
        self.at(located.dir.clone(), None).config == located.config
    }

    /// Whether [`Self::variables`] belong to this host alone, so one that is
    /// set says the host is meant to be there: `moat init` then names a
    /// directory they point at that does not exist yet. `false` for a
    /// variable other programs read too (`XDG_CONFIG_HOME`).
    fn variables_are_the_hosts(&self) -> bool {
        true
    }
}

/// A configuration directory under the XDG one: the directory variable
/// [`Self::own`] names when it is set, else `<$XDG_CONFIG_HOME>/<app>`, else
/// `~/<dir_name>` (Crush, Kilo Code). An empty value is unset. `XDG_CONFIG_HOME`
/// is read by many programs, so a value of it says nothing about whether the
/// host is installed ([`Locate::variables_are_the_hosts`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct XdgDir {
    /// The host's own variable, which names the directory itself.
    pub own: &'static str,
    /// `XDG_CONFIG_HOME` and [`Self::own`], in that order.
    pub variables: &'static [&'static str; 2],
    /// The directory's name under `XDG_CONFIG_HOME`.
    pub app: &'static str,
    /// The directory's path under the home directory by default.
    pub dir_name: &'static str,
    /// The hook file, relative to the directory.
    pub file: &'static str,
}

impl XdgDir {
    /// The XDG variable every such directory is under.
    pub const BASE: &'static str = "XDG_CONFIG_HOME";
}

impl Locate for XdgDir {
    fn variables(&self) -> &'static [&'static str] {
        self.variables
    }

    fn moved(&self, get: &dyn Fn(&str) -> Option<String>) -> bool {
        self.variables
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
        let dir = match (set(self.own), set(Self::BASE)) {
            (Some(dir), _) => absolute(Path::new(&dir))?,
            (None, Some(base)) => absolute(&Path::new(&base).join(self.app))?,
            (None, None) => os_home.join(self.dir_name),
        };
        Ok(self.at(dir, None))
    }

    fn at(&self, dir: PathBuf, config: Option<PathBuf>) -> Located {
        let config = config.unwrap_or_else(|| dir.join(self.file));
        Located { dir, config }
    }

    fn default_for(&self, home: &Path) -> Located {
        self.at(home.join(self.dir_name), None)
    }

    fn variables_are_the_hosts(&self) -> bool {
        false
    }
}

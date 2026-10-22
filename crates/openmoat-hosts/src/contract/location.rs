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
}

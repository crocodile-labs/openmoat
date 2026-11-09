//! Where Antigravity CLI keeps its files (`/docs/hooks`, `/docs/settings`):
//! its own directory is `~/.gemini/antigravity-cli`, which tells OpenMoat it
//! is installed; the hook file is `~/.gemini/config/hooks.json`, shared with
//! the Antigravity app and IDE. No variable moves either: the documentation
//! names none, so the only thing that moves them is `~` itself.

use std::io;
use std::path::{Path, PathBuf};

use crate::contract::{Locate, Located};

/// The directory holding `settings.json`, under the home directory.
pub(super) const DIR_NAME: &str = ".gemini/antigravity-cli";
/// The hook file's name in its own directory.
pub(super) const HOOK_FILE: &str = "hooks.json";
/// The hook file's directory, under the home directory.
const HOOK_DIR: [&str; 2] = [".gemini", "config"];

/// The hook file under the home directory `home`.
fn hook_file_in(home: &Path) -> PathBuf {
    HOOK_DIR
        .iter()
        .fold(home.to_path_buf(), |path, part| path.join(part))
        .join(HOOK_FILE)
}

/// The home directory of the default configuration directory.
fn home_of(dir: &Path) -> Option<PathBuf> {
    let at = dir.parent()?;
    if dir.file_name()? != "antigravity-cli" || at.file_name()? != ".gemini" {
        return None;
    }
    at.parent().map(Path::to_path_buf)
}

/// Antigravity CLI's location rules.
pub(super) struct Antigravity;

pub(super) static LOCATE: Antigravity = Antigravity;

impl Locate for Antigravity {
    /// None documented.
    fn variables(&self) -> &'static [&'static str] {
        &[]
    }

    fn moved(&self, _get: &dyn Fn(&str) -> Option<String>) -> bool {
        false
    }

    fn resolve(
        &self,
        _get: &dyn Fn(&str) -> Option<String>,
        os_home: &Path,
        _absolute: &dyn Fn(&Path) -> io::Result<PathBuf>,
    ) -> io::Result<Located> {
        Ok(self.default_for(os_home))
    }

    fn at(&self, dir: PathBuf, config: Option<PathBuf>) -> Located {
        let config = config.unwrap_or_else(|| {
            let home = home_of(&dir).unwrap_or_else(|| dir.clone());
            hook_file_in(&home)
        });
        Located { dir, config }
    }

    fn default_for(&self, home: &Path) -> Located {
        Located {
            dir: home.join(DIR_NAME),
            config: hook_file_in(home),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hook_file_is_outside_the_cli_directory() {
        if cfg!(windows) {
            return;
        }
        let at = LOCATE.default_for(Path::new("/h"));
        assert_eq!(at.dir, PathBuf::from("/h/.gemini/antigravity-cli"));
        assert_eq!(at.config, PathBuf::from("/h/.gemini/config/hooks.json"));
        assert!(!LOCATE.moved(&|_| Some("/elsewhere".to_owned())));
        assert_eq!(LOCATE.at(at.dir.clone(), None), at);
        let kept = PathBuf::from("/o/hooks.json");
        assert_eq!(LOCATE.at(at.dir.clone(), Some(kept.clone())).config, kept);
    }
}

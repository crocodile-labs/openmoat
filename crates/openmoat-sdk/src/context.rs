//! Where the agent runs: the roots a policy's `~` and `${project}` name, and
//! the directory relative paths are taken from.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use openmoat_core::EvalContext;

use crate::error::Error;

/// The environment an engine decides for. Paths are absolute and
/// slash-separated (`/home/me`, `C:/Users/me`).
///
/// Its JSON form, which the JavaScript package sends, has the same field names;
/// `home` and `cwd` are required, the rest optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    home: String,
    cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    real_home: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    real_project: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    moved_dirs: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    case_insensitive_paths: bool,
}

impl Context {
    /// The user's home directory, for `~`, and the directory the agent works
    /// in, for relative paths. No project: rules naming `${project}` match
    /// nothing until [`Self::project`] names one.
    #[must_use]
    pub fn new(home: impl Into<String>, cwd: impl Into<String>) -> Self {
        Self {
            home: home.into(),
            cwd: cwd.into(),
            project: None,
            real_home: None,
            real_project: None,
            moved_dirs: BTreeMap::new(),
            case_insensitive_paths: false,
        }
    }

    /// The project root the person trusts, for `${project}`. Never the home
    /// directory, one of its ancestors or a filesystem root: that would make
    /// every project-scoped allow apply to the whole disk.
    #[must_use]
    pub fn project(mut self, root: impl Into<String>) -> Self {
        self.project = Some(root.into());
        self
    }

    /// The home directory with its symlinks resolved, when that differs.
    #[must_use]
    pub fn real_home(mut self, path: impl Into<String>) -> Self {
        self.real_home = Some(path.into());
        self
    }

    /// The project root with its symlinks resolved, when that differs
    /// (macOS `/tmp/x` is `/private/tmp/x`).
    #[must_use]
    pub fn real_project(mut self, path: impl Into<String>) -> Self {
        self.real_project = Some(path.into());
        self
    }

    /// A directory an environment variable moved (`~/.claude` to
    /// `/srv/claude`): rules naming `default` also match under `moved`.
    #[must_use]
    pub fn moved_dir(mut self, default: impl Into<String>, moved: impl Into<String>) -> Self {
        self.moved_dirs.insert(default.into(), moved.into());
        self
    }

    /// Whether file names compare ignoring case, as on the default macOS and
    /// Windows file systems. Off unless set.
    #[must_use]
    pub fn case_insensitive_paths(mut self, on: bool) -> Self {
        self.case_insensitive_paths = on;
        self
    }

    /// The working directory relative paths are taken from.
    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// The engine's form, after checking every root is an absolute,
    /// slash-separated path.
    pub(crate) fn to_core(&self) -> Result<EvalContext, Error> {
        let roots = [("home", Some(&self.home)), ("cwd", Some(&self.cwd))]
            .into_iter()
            .chain([
                ("project", self.project.as_ref()),
                ("real_home", self.real_home.as_ref()),
                ("real_project", self.real_project.as_ref()),
            ])
            .chain(self.moved_dirs.values().map(|m| ("moved_dirs", Some(m))));
        for (name, value) in roots {
            if let Some(path) = value
                && !is_absolute(path)
            {
                return Err(Error::Context {
                    message: format!(
                        "`{name}` must be an absolute, slash-separated path, not `{path}`"
                    ),
                });
            }
        }
        Ok(EvalContext {
            home: self.home.clone(),
            project: self.project.clone(),
            real_home: self.real_home.clone(),
            real_project: self.real_project.clone(),
            moved_dirs: self.moved_dirs.clone().into_iter().collect(),
            cwd: self.cwd.clone(),
            case_insensitive_paths: self.case_insensitive_paths,
        })
    }
}

/// `/…` or a drive root `X:/…`, with no backslash.
fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    let rooted = bytes.first() == Some(&b'/')
        || (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":/");
    rooted && !path.contains('\\')
}

#[cfg(test)]
mod tests {
    use super::{Context, is_absolute};

    #[test]
    fn roots_must_be_absolute_and_slash_separated() {
        assert!(is_absolute("/home/me") && is_absolute("C:/Users/me"));
        for bad in ["", "home", "./x", "C:", "C:\\Users\\me", "~/x"] {
            assert!(!is_absolute(bad), "{bad}");
        }
        assert!(Context::new("/h", "/p").project("/p").to_core().is_ok());
        let err = Context::new("/h", "p").to_core().unwrap_err();
        assert!(err.to_string().contains("`cwd`"), "{err}");
        let err = Context::new("/h", "/p")
            .moved_dir("~/.claude", "srv")
            .to_core()
            .unwrap_err();
        assert!(err.to_string().contains("moved_dirs"), "{err}");
    }

    #[test]
    fn json_form_has_the_builder_fields() {
        let ctx = Context::new("/h", "/p")
            .project("/p")
            .real_project("/private/p")
            .moved_dir("~/.claude", "/srv/claude")
            .case_insensitive_paths(true);
        let text = serde_json::to_string(&ctx).unwrap();
        assert_eq!(
            text,
            r#"{"home":"/h","cwd":"/p","project":"/p","real_project":"/private/p","moved_dirs":{"~/.claude":"/srv/claude"},"case_insensitive_paths":true}"#
        );
        assert_eq!(serde_json::from_str::<Context>(&text).unwrap(), ctx);
        assert!(
            serde_json::from_str::<Context>(r#"{"home":"/h","cwd":"/p","proj":"/p"}"#).is_err()
        );
    }
}

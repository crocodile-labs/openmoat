//! Paths under the person's home directory shown as `~/…`.

use std::path::Path;

/// The home directory to shorten paths by; none when it is not known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Paths {
    home: Option<String>,
}

impl Paths {
    /// This user's home directory (`HOME`, `USERPROFILE` on Windows).
    pub fn detect() -> Self {
        Self::under(crate::home::user_home().ok().as_deref())
    }

    /// Shorten paths under `home`. A home that is a filesystem root, or
    /// empty, shortens nothing: every path would start with it.
    pub fn under(home: Option<&Path>) -> Self {
        let home = home
            .map(|h| h.to_string_lossy().trim_end_matches(['/', '\\']).to_owned())
            .filter(|h| !h.is_empty() && !h.ends_with(':'));
        Self { home }
    }

    /// `text` with every path under the home directory as `~/…`, and the home
    /// directory itself as `~`. A longer name that only starts like it
    /// (`/home/ann` in `/home/anna/x`) is left alone.
    pub fn shorten(&self, text: &str) -> String {
        let Some(home) = self.home.as_deref() else {
            return text.to_owned();
        };
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.find(home) {
            let after = &rest[at + home.len()..];
            let starts_path = at == 0 || !continues_name(rest[..at].chars().next_back());
            let ends_home = after
                .chars()
                .next()
                .is_none_or(|c| matches!(c, '/' | '\\') || !continues_name(Some(c)));
            out.push_str(&rest[..at]);
            if starts_path && ends_home {
                out.push('~');
            } else {
                out.push_str(home);
            }
            rest = after;
        }
        out.push_str(rest);
        out
    }

    /// One path, shortened.
    pub fn path(&self, path: &Path) -> String {
        self.shorten(&path.to_string_lossy())
    }
}

/// Whether `c` could be part of a file name next to the home directory's text.
fn continues_name(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '\\'))
}

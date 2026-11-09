//! Files OpenMoat owns whole: pi's extension, OpenClaw's and OpenCode's plugins,
//! Cline's hook script. Each is a script in the host's `integration/` folder
//! with one line naming the binary and one naming the state directory the
//! guard is given as `--home` (ADR-071), which `moat init` fills in
//! ([`Syntax`]); the CLI writes the result whole, pins it whole and deletes it
//! on `moat uninstall`.

use std::fmt;

use thiserror::Error;

/// The language of an owned file, which says how its binary line is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// `const MOAT = __MOAT_BINARY__;`, filled in with the path as a JSON
    /// string (a JavaScript string literal); `const MOAT_HOME = __MOAT_HOME__;`
    /// likewise with the state directory's word ([`crate::encode_home`]).
    JavaScript,
    /// `MOAT=__MOAT_BINARY__`, filled in with the path in single quotes, each
    /// `'` in it written `'\''` (a POSIX shell word); `MOAT_STATE=__MOAT_HOME__`
    /// likewise with the state directory's word.
    PosixShell,
}

impl Syntax {
    /// The line `init` fills in with the binary's path.
    const fn placeholder(self) -> &'static str {
        match self {
            Self::JavaScript => "const MOAT = __MOAT_BINARY__;",
            Self::PosixShell => "MOAT=__MOAT_BINARY__",
        }
    }

    /// How a filled-in binary line begins.
    const fn filled(self) -> &'static str {
        match self {
            Self::JavaScript => "const MOAT = ",
            Self::PosixShell => "MOAT=",
        }
    }

    /// The line `init` fills in with the state directory.
    const fn home_placeholder(self) -> &'static str {
        match self {
            Self::JavaScript => "const MOAT_HOME = __MOAT_HOME__;",
            Self::PosixShell => "MOAT_STATE=__MOAT_HOME__",
        }
    }

    /// How a filled-in state directory line begins.
    const fn home_filled(self) -> &'static str {
        match self {
            Self::JavaScript => "const MOAT_HOME = ",
            Self::PosixShell => "MOAT_STATE=",
        }
    }

    /// The line beginning `filled` that holds `value`.
    fn line(self, filled: &str, value: &str) -> String {
        match self {
            Self::JavaScript => format!("{filled}{};", serde_json::Value::from(value)),
            Self::PosixShell => format!("{filled}'{}'", value.replace('\'', r"'\''")),
        }
    }

    /// The binary a filled-in line's literal (what follows [`Self::filled`])
    /// names; `None` when it is not a literal [`Self::line`] writes.
    fn binary(self, literal: &str) -> Option<String> {
        match self {
            Self::JavaScript => serde_json::from_str(literal.strip_suffix(';')?).ok(),
            Self::PosixShell => {
                let inner = literal.strip_prefix('\'')?.strip_suffix('\'')?;
                // Every `'` inside is the `'\''` this syntax writes for one.
                let parts: Vec<&str> = inner.split(r"'\''").collect();
                if parts.iter().any(|p| p.contains('\'')) {
                    return None;
                }
                Some(parts.join("'"))
            }
        }
    }
}

/// A file OpenMoat writes whole for a host, from its source.
pub struct OwnedFile {
    /// What the file is, as errors name it (`pi extension`).
    pub name: &'static str,
    /// The source, with its [`Syntax`]'s binary line once.
    pub source: &'static str,
    /// How every copy `init` writes begins, whichever binary it names.
    pub first_line: &'static str,
    /// The language of the source.
    pub syntax: Syntax,
}

impl fmt::Debug for OwnedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OwnedFile({})", self.name)
    }
}

/// A source without exactly one binary line of its syntax.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the {0} source has no single `{1}` line")]
pub struct OwnedFileError(pub &'static str, pub &'static str);

impl OwnedFile {
    /// The file as `init` writes it for `binary`, whose guard is given the
    /// state directory `home` as `--home` (ADR-071).
    ///
    /// # Errors
    /// When the source does not hold the binary line and the state directory
    /// line exactly once each.
    pub fn text(&self, binary: &str, home: &str) -> Result<String, OwnedFileError> {
        let syntax = self.syntax;
        let mut text = self.source.to_owned();
        let lines = [
            (syntax.placeholder(), syntax.filled(), binary.to_owned()),
            (
                syntax.home_placeholder(),
                syntax.home_filled(),
                crate::encode_home(home),
            ),
        ];
        for (placeholder, filled, value) in lines {
            if text.matches(placeholder).count() != 1 {
                return Err(OwnedFileError(self.name, placeholder));
            }
            text = text.replacen(placeholder, &syntax.line(filled, &value), 1);
        }
        // `sh` reads a `\r` as part of a word: a script checked out with CRLF
        // endings (Windows) is written with LF, as `.gitattributes` keeps it.
        Ok(match self.syntax {
            Syntax::PosixShell => text.replace("\r\n", "\n"),
            Syntax::JavaScript => text,
        })
    }

    /// Whether `text` is a copy `init` wrote, for this binary or another.
    #[must_use]
    pub fn is_ours(&self, text: &str) -> bool {
        text.starts_with(self.first_line)
    }

    /// The binary a copy `init` wrote runs, for "points at another binary".
    #[must_use]
    pub fn binary(&self, text: &str) -> Option<String> {
        let filled = self.syntax.filled();
        let line = text.lines().find(|l| l.starts_with(filled))?;
        self.syntax.binary(line.strip_prefix(filled)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(syntax: Syntax, source: &'static str) -> OwnedFile {
        OwnedFile {
            name: "test file",
            source,
            first_line: "# test",
            syntax,
        }
    }

    #[test]
    fn a_shell_binary_line_is_one_single_quoted_word_read_back_as_written() {
        let sh = file(
            Syntax::PosixShell,
            "# test\nMOAT=__MOAT_BINARY__\nMOAT_STATE=__MOAT_HOME__\nexec \"$MOAT\"\n",
        );
        for binary in [
            "/usr/local/bin/openmoat",
            "/Users/o'brien/bin/openmoat",
            "/a b/$x`y`",
        ] {
            let text = sh.text(binary, "/h/.moat").unwrap();
            assert!(sh.is_ours(&text));
            assert_eq!(sh.binary(&text).as_deref(), Some(binary), "{text}");
            assert_eq!(text.matches("MOAT=").count(), 1);
        }
        assert_eq!(
            sh.text("/o'b", "/a b/.moat").unwrap(),
            "# test\nMOAT='/o'\\''b'\nMOAT_STATE='/a+20b/.moat'\nexec \"$MOAT\"\n"
        );
        // A line `init` did not write names no binary.
        assert_eq!(sh.binary("MOAT=/bin/sh\n"), None);
        assert_eq!(sh.binary("MOAT='a'b'\n"), None);
    }

    #[test]
    fn a_javascript_binary_line_is_a_json_string() {
        let js = file(
            Syntax::JavaScript,
            "# test\nconst MOAT = __MOAT_BINARY__;\nconst MOAT_HOME = __MOAT_HOME__;\n",
        );
        let text = js
            .text("C:\\moat\\openmoat.exe", "C:/Users/me/.moat")
            .unwrap();
        assert!(text.contains(r#"const MOAT = "C:\\moat\\openmoat.exe";"#));
        assert!(text.contains(r#"const MOAT_HOME = "C:/Users/me/.moat";"#));
        assert_eq!(js.binary(&text).as_deref(), Some("C:\\moat\\openmoat.exe"));
    }

    #[test]
    fn a_source_without_one_binary_line_of_its_syntax_is_an_error() {
        let wrong = file(
            Syntax::PosixShell,
            "# test\nconst MOAT = __MOAT_BINARY__;\n",
        );
        assert_eq!(
            wrong.text("/x", "/h"),
            Err(OwnedFileError("test file", "MOAT=__MOAT_BINARY__"))
        );
        let no_home = file(Syntax::PosixShell, "# test\nMOAT=__MOAT_BINARY__\n");
        assert_eq!(
            no_home.text("/x", "/h"),
            Err(OwnedFileError("test file", "MOAT_STATE=__MOAT_HOME__"))
        );
    }
}

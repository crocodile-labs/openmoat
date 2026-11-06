//! Colour for the human output: only when standard output is a terminal, and
//! never when `NO_COLOR` is set to anything but the empty string
//! (<https://no-color.org>). A pipe, a file or a test gets plain text.

use std::ffi::OsString;
use std::io::IsTerminal as _;

use super::Mark;

/// Whether to colour, decided once per command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    colour: bool,
}

impl Style {
    /// For this process: its standard output and its `NO_COLOR`.
    pub fn detect() -> Self {
        Self::new(
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR"),
        )
    }

    /// Colour only on a `terminal` and without a non-empty `no_color`.
    pub fn new(terminal: bool, no_color: Option<OsString>) -> Self {
        Self {
            colour: terminal && no_color.is_none_or(|v| v.is_empty()),
        }
    }

    /// The mark's symbol, green, yellow, red or dim.
    pub fn mark(self, mark: Mark) -> String {
        self.tint(mark, mark.symbol())
    }

    /// `text` in the colour of `mark`: green, yellow, red or dim.
    pub fn tint(self, mark: Mark, text: &str) -> String {
        let code = match mark {
            Mark::Ok => "32",
            Mark::Attention => "33",
            Mark::Broken => "31",
            Mark::Info | Mark::Absent => "2",
        };
        self.paint(code, text)
    }

    pub fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }

    pub fn dim(self, text: &str) -> String {
        self.paint("2", text)
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.colour {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}

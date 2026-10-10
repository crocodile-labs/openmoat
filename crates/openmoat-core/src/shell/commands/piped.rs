//! What a command writes to a pipe, when the command line shows it.
//!
//! A shell reading stdin after the pipe runs that text as its program, so
//! `cat <<'EOF' | sh` is classified like `sh <<'EOF'`. `printf` and some
//! `echo`s expand escapes and formats (`printf '\x63at .env'` prints
//! `cat .env`); only `\n` is read, and any other escape or a `printf` format
//! makes the text unknown, so a shell that runs it asks.

use super::SimpleCommand;
use crate::shell::tokens::basename;

/// Text a command passes on through a pipe.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Piped {
    /// The text, as the shell after the pipe reads it.
    Text(String),
    /// The program prints text the command line does not show.
    Unknown(String),
}

impl Piped {
    pub(super) fn text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Unknown(_) => None,
        }
    }

    pub(super) fn unknown(&self) -> Option<&str> {
        match self {
            Self::Unknown(program) => Some(program),
            Self::Text(_) => None,
        }
    }
}

/// What `cmd` writes to a pipe: a bare `cat` passes on its here-document or
/// here-string, `echo` and `printf` their arguments.
pub(super) fn data(cmd: &SimpleCommand) -> Option<Piped> {
    let argv: Vec<&str> = cmd.words.iter().map(|w| w.text.as_str()).collect();
    match argv.as_slice() {
        [cat] | [cat, "-"] if basename(cat) == "cat" && cmd.reads.is_empty() => Some(Piped::Text(
            cmd.stdin_texts().collect::<Vec<_>>().join("\n"),
        )),
        [program, operands @ ..] if matches!(basename(program), "echo" | "printf") => {
            let printed: Vec<&str> = operands
                .iter()
                .copied()
                .skip_while(|a| matches!(*a, "-n" | "-e" | "-E" | "--"))
                .collect();
            let format = basename(program) == "printf" && printed.iter().any(|a| a.contains('%'));
            let text = expand_newlines(&printed.join(" ")).filter(|_| !format);
            Some(text.map_or_else(|| Piped::Unknown(basename(program).to_owned()), Piped::Text))
        }
        _ => None,
    }
}

/// `text` with each `\n` turned into a newline; `None` when it holds any
/// other backslash, whose meaning differs between `printf` and the `echo`s.
fn expand_newlines(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.next()? == 'n' => out.push('\n'),
            '\\' => return None,
            _ => out.push(c),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::expand_newlines;

    #[test]
    fn only_newline_escapes_are_read() {
        assert_eq!(expand_newlines("ls\\npwd").as_deref(), Some("ls\npwd"));
        assert_eq!(expand_newlines("plain").as_deref(), Some("plain"));
        for text in ["\\x63at .env", "\\\\n", "\\101", "\\t", "end\\"] {
            assert_eq!(expand_newlines(text), None, "{text}");
        }
    }
}

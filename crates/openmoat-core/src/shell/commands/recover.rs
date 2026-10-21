//! Reading a command line as bash runs it, where the lexer alone would refuse
//! it and leave the whole line unread.

use crate::lexer::{self, LexError, Token};

/// Most times a line is lexed again: one per here-document left open, and one
/// for a trailing backslash.
const MAX_RELEXES: usize = 8;

/// Lex `command` as bash runs it. Bash ends a here-document that has no
/// delimiter line at the end of the input (with a warning) and keeps a
/// backslash that ends the input as a character; the lexer refuses both, which
/// would leave the whole line unread, so the line is lexed again with the
/// delimiter line or the backslash written out.
pub(super) fn lex_like_bash(command: &str) -> Result<Vec<Token>, LexError> {
    let mut line = command.to_owned();
    for _ in 0..MAX_RELEXES {
        match lexer::lex(&line) {
            Err(LexError::UnterminatedHereDoc { delimiter }) => {
                line = format!("{line}\n{delimiter}\n");
            }
            Err(LexError::TrailingBackslash) => line.push('\\'),
            result => return result,
        }
    }
    lexer::lex(&line)
}

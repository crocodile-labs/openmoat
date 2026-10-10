//! POSIX-shell lexer sufficient for policy classification.
//!
//! The lexer does **not** execute anything and does not expand variables; it
//! produces words and control operators so that the classifier (`shell/`) can decompose a
//! command line into simple commands, redirections and nested commands.
//!
//! Supported syntax:
//! - whitespace and newlines; `#` comments at word start;
//! - single quotes, double quotes (with `\"`, `\\`, `\$`, `` \` `` escapes), backslash
//!   escapes outside quotes;
//! - control operators `|`, `||`, `&`, `&&`, `;`, `(`, `)`, newline;
//! - redirections `<`, `>`, `>>`, `<>`, `&>`, `&>>`, `<&`, `>&`, with optional
//!   leading file-descriptor digits (`2>&1`, `3<file`);
//! - here-documents `<<` / `<<-`: the body (up to the delimiter line) is stdin data,
//!   exposed on a token at the position of the `<<`. With an unquoted delimiter the shell
//!   expands `$( … )`, backticks and `$VAR` in the body, so they are captured as for a
//!   word; a quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) keeps the body literal;
//! - here-strings `<<<`: a redirect operator whose following word is stdin data; the
//!   word is lexed like any other, so its `$( … )` substitutions are still captured;
//! - command substitution `$( … )` (nesting aware) and backticks; the inner text is
//!   attached to the containing word so it can be classified as its own command.
//!
//! Anything the lexer cannot make sense of is an error; the engine maps lexer
//! errors to `ask`, never to `allow`. Brace expansion (`brace.rs`) is a separate
//! step the classifier runs on the tokens, so policy patterns are lexed as written.

mod brace;
mod heredoc;
mod operator;
#[cfg(test)]
mod tests;

use std::fmt;
use std::ops::Range;

pub use brace::{MAX_BRACE_WORDS, expand_braces};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Pipe,
    And,
    Or,
    Sequence,
    Background,
    OpenParen,
    CloseParen,
    RedirectIn,
    RedirectOut,
    RedirectAppend,
    RedirectReadWrite,
    /// `<&` / `>&`: duplicates a descriptor; the target is a descriptor or `-`.
    DuplicateDescriptor,
    /// `<<<`: the following word is the command's stdin, not a file.
    HereString,
}

impl Operator {
    #[must_use]
    pub fn is_separator(self) -> bool {
        matches!(
            self,
            Self::Pipe | Self::And | Self::Or | Self::Sequence | Self::Background
        )
    }

    #[must_use]
    pub fn is_grouping(self) -> bool {
        matches!(self, Self::OpenParen | Self::CloseParen)
    }

    #[must_use]
    pub fn is_redirect(self) -> bool {
        matches!(
            self,
            Self::RedirectIn
                | Self::RedirectOut
                | Self::RedirectAppend
                | Self::RedirectReadWrite
                | Self::DuplicateDescriptor
                | Self::HereString
        )
    }

    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Pipe => "|",
            Self::And => "&&",
            Self::Or => "||",
            Self::Sequence => ";",
            Self::Background => "&",
            Self::OpenParen => "(",
            Self::CloseParen => ")",
            Self::RedirectIn => "<",
            Self::RedirectOut => ">",
            Self::RedirectAppend => ">>",
            Self::RedirectReadWrite => "<>",
            Self::DuplicateDescriptor => ">&",
            Self::HereString => "<<<",
        }
    }
}

/// A shell word with quoting removed and nested commands extracted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Word {
    /// The word with quotes and escapes resolved. `$VAR` text is preserved.
    pub text: String,
    /// True if any part of the word was quoted (affects glob/host heuristics).
    pub quoted: bool,
    /// True if an unquoted, unescaped `*`, `?` or `[` is part of the word: the
    /// shell replaces such a word with the file names it matches.
    pub glob: bool,
    /// Byte ranges of `text` that came from single quotes: the shell does not
    /// expand a `$` inside them, so it names no variable.
    pub literal: Vec<Range<usize>>,
    /// Byte ranges of `text` taken from unquoted, unescaped source: only there
    /// are `{`, `,` and `}` brace syntax (`brace.rs`).
    pub unquoted: Vec<Range<usize>>,
    /// Inner text of every `$( … )` / `` ` … ` `` found inside the word.
    pub substitutions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Word(Word),
    Operator(Operator),
    /// A here-document body: stdin data. Unless `literal`, `body` is expanded like a
    /// double-quoted word (escapes resolved, substitutions captured).
    HereDoc {
        body: Word,
        literal: bool,
    },
}

/// Why a command line could not be tokenised. Any of these makes the action `ask`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LexError {
    #[error("unterminated single quote")]
    UnterminatedSingleQuote,
    #[error("unterminated double quote")]
    UnterminatedDoubleQuote,
    #[error("unterminated `$(` command substitution")]
    UnterminatedSubstitution,
    #[error("unterminated backtick substitution")]
    UnterminatedBacktick,
    #[error("here-document `{delimiter}` has no terminating line")]
    UnterminatedHereDoc { delimiter: String },
    #[error("command ends with a backslash")]
    TrailingBackslash,
    #[error("command exceeds {max} bytes")]
    TooLong { max: usize },
    #[error("braces expand past what can be checked ({MAX_BRACE_WORDS} words)")]
    TooManyBraceWords,
}

/// Upper bound on input size; larger commands are refused (and therefore `ask`).
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;

/// Tokenise a command line.
pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    if input.len() > MAX_COMMAND_BYTES {
        return Err(LexError::TooLong {
            max: MAX_COMMAND_BYTES,
        });
    }
    Lexer::new(input).run()
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    tokens: Vec<Token>,
    pending_heredocs: Vec<heredoc::Pending>,
    current: Option<Word>,
}

impl Lexer {
    fn new(src: &str) -> Self {
        Self {
            chars: src.chars().collect(),
            pos: 0,
            tokens: Vec::new(),
            pending_heredocs: Vec::new(),
            current: None,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn word(&mut self) -> &mut Word {
        self.current.get_or_insert_with(Word::default)
    }

    fn flush_word(&mut self) {
        if let Some(w) = self.current.take() {
            if let Some(pending) = self.awaiting_delimiter() {
                // The word following `<<` is the delimiter, not an argument.
                pending.literal |= w.quoted;
                pending.delimiter = Some(w.text);
                return;
            }
            self.tokens.push(Token::Word(w));
        }
    }

    fn push_operator(&mut self, op: Operator) {
        self.flush_word();
        self.tokens.push(Token::Operator(op));
    }

    fn run(mut self) -> Result<Vec<Token>, LexError> {
        while let Some(c) = self.peek() {
            if let Some(first) = operator::First::of(c) {
                self.operator(first);
                continue;
            }
            match c {
                ' ' | '\t' | '\r' => {
                    self.bump();
                    self.flush_word();
                }
                '\n' => {
                    self.bump();
                    self.flush_word();
                    self.consume_heredoc_bodies()?;
                    self.tokens.push(Token::Operator(Operator::Sequence));
                }
                '#' if self.current.is_none() => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                '\'' => {
                    // `$'…'` (ANSI-C quoting) decodes escapes such as `\x24`; its
                    // text is not marked literal, so it is scanned as before.
                    let ansi_c = self.pos > 0 && self.chars[self.pos - 1] == '$';
                    self.bump();
                    self.single_quoted(ansi_c)?;
                }
                '"' => {
                    self.bump();
                    self.double_quoted()?;
                }
                '\\' => {
                    self.bump();
                    match self.bump() {
                        Some('\n') => {}
                        Some(escaped) => {
                            if let Some(pending) = self.awaiting_delimiter() {
                                pending.literal = true;
                            }
                            self.word().text.push(escaped);
                        }
                        None => return Err(LexError::TrailingBackslash),
                    }
                }
                '`' => {
                    self.bump();
                    self.backtick()?;
                }
                '$' if self.peek_at(1) == Some('(') => {
                    self.pos += 2;
                    self.dollar_paren()?;
                }
                _ => {
                    self.bump();
                    let word = self.word();
                    word.glob |= matches!(c, '*' | '?' | '[');
                    let at = word.text.len();
                    word.text.push(c);
                    match word.unquoted.last_mut() {
                        Some(run) if run.end == at => run.end = word.text.len(),
                        _ => word.unquoted.push(at..word.text.len()),
                    }
                }
            }
        }
        self.flush_word();
        // `<<` at end of input with no delimiter: treat as plain input redirect.
        if let Some(delimiter) = self
            .pending_heredocs
            .iter()
            .find_map(|h| h.delimiter.clone())
        {
            return Err(LexError::UnterminatedHereDoc { delimiter });
        }
        Ok(self.tokens)
    }

    fn single_quoted(&mut self, ansi_c: bool) -> Result<(), LexError> {
        let word = self.word();
        word.quoted = true;
        let start = word.text.len();
        loop {
            match self.bump() {
                Some('\'') => {
                    let word = self.word();
                    if !ansi_c && word.text.len() > start {
                        word.literal.push(start..word.text.len());
                    }
                    return Ok(());
                }
                Some(c) => self.word().text.push(c),
                None => return Err(LexError::UnterminatedSingleQuote),
            }
        }
    }

    fn double_quoted(&mut self) -> Result<(), LexError> {
        self.word().quoted = true;
        self.expanding(Some('"'))
    }

    /// Text where only `\`, `$( … )`, backticks and `$VAR` are special: the inside of
    /// double quotes (`close` = `"`) or an unquoted here-document body (`close` = `None`).
    fn expanding(&mut self, close: Option<char>) -> Result<(), LexError> {
        loop {
            match self.bump() {
                Some(c) if Some(c) == close => return Ok(()),
                Some('\\') => match self.bump() {
                    Some(c @ ('\\' | '$' | '`')) => self.word().text.push(c),
                    Some(c) if Some(c) == close => self.word().text.push(c),
                    Some('\n') => {}
                    Some(c) => {
                        self.word().text.push('\\');
                        self.word().text.push(c);
                    }
                    None if close.is_none() => self.word().text.push('\\'),
                    None => return Err(LexError::UnterminatedDoubleQuote),
                },
                Some('`') => self.backtick()?,
                Some('$') if self.peek() == Some('(') => {
                    self.bump();
                    self.dollar_paren()?;
                }
                Some(c) => self.word().text.push(c),
                None if close.is_none() => return Ok(()),
                None => return Err(LexError::UnterminatedDoubleQuote),
            }
        }
    }

    /// `$( … )` with nesting; the inner text is recorded as a substitution.
    fn dollar_paren(&mut self) -> Result<(), LexError> {
        let start = self.pos;
        let mut depth = 1usize;
        let mut in_single = false;
        let mut in_double = false;
        while let Some(c) = self.bump() {
            match c {
                '\\' => {
                    self.bump();
                }
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                '(' if !in_single => depth += 1,
                ')' if !in_single => {
                    depth -= 1;
                    if depth == 0 {
                        let inner: String = self.chars[start..self.pos - 1].iter().collect();
                        let w = self.word();
                        w.quoted = true;
                        w.substitutions.push(inner.trim().to_owned());
                        w.text.push_str("$(…)");
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(LexError::UnterminatedSubstitution)
    }

    fn backtick(&mut self) -> Result<(), LexError> {
        let start = self.pos;
        while let Some(c) = self.bump() {
            match c {
                '\\' => {
                    self.bump();
                }
                '`' => {
                    let inner: String = self.chars[start..self.pos - 1].iter().collect();
                    let w = self.word();
                    w.quoted = true;
                    w.substitutions.push(inner.trim().to_owned());
                    w.text.push_str("`…`");
                    return Ok(());
                }
                _ => {}
            }
        }
        Err(LexError::UnterminatedBacktick)
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Word(w) => f.write_str(&w.text),
            Self::Operator(op) => f.write_str(op.symbol()),
            Self::HereDoc { .. } => f.write_str("<<heredoc"),
        }
    }
}

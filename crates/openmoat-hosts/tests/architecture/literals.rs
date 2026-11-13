//! The string literals of a Rust source file, so a host named in a comment
//! (documentation of what a host does) is not counted, and one named in code
//! is wherever it stands.

/// One string literal.
pub struct Literal {
    /// The 0-based line it starts on.
    pub line: usize,
    /// Its text, escaped quotes unescaped.
    pub text: String,
    /// Whether a `:` follows it, as a JSON key's does (`"cursor": cursor`).
    pub key: bool,
}

/// Each string literal of `source` (`"…"`, `b"…"`, `r#"…"#`). Comments and
/// character literals are skipped.
pub fn literals(source: &str) -> Vec<Literal> {
    let chars: Vec<char> = source.chars().collect();
    let mut lexer = Lexer {
        chars: &chars,
        at: 0,
        line: 0,
    };
    let mut out = Vec::new();
    while let Some(c) = lexer.peek(0) {
        match c {
            '/' if lexer.peek(1) == Some('/') => {
                while lexer.peek(0).is_some_and(|c| c != '\n') {
                    lexer.at += 1;
                }
            }
            '/' if lexer.peek(1) == Some('*') => {
                lexer.at += 2;
                while lexer.peek(0).is_some()
                    && !(lexer.peek(0) == Some('*') && lexer.peek(1) == Some('/'))
                {
                    lexer.bump();
                }
                lexer.at += 2;
            }
            '"' => {
                let line = lexer.line;
                lexer.at += 1;
                let text = lexer.quoted(0, false);
                out.push(lexer.literal(line, text));
            }
            '\'' => lexer.char_or_lifetime(),
            c if c.is_alphanumeric() || c == '_' => {
                let start = lexer.at;
                while lexer
                    .peek(0)
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    lexer.at += 1;
                }
                let word: String = chars[start..lexer.at].iter().collect();
                if word == "r" || word == "br" {
                    let hashes = chars[lexer.at..].iter().take_while(|c| **c == '#').count();
                    if lexer.peek(hashes) == Some('"') {
                        let line = lexer.line;
                        lexer.at += hashes + 1;
                        let text = lexer.quoted(hashes, true);
                        out.push(lexer.literal(line, text));
                    }
                }
            }
            _ => lexer.bump(),
        }
    }
    out
}

struct Lexer<'a> {
    chars: &'a [char],
    at: usize,
    line: usize,
}

impl Lexer<'_> {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    /// The literal just read, which started on `line`.
    fn literal(&self, line: usize, text: String) -> Literal {
        let after = self.chars[self.at..]
            .iter()
            .copied()
            .skip_while(|c| *c == ' ');
        let mut after = after.take(2);
        let key = after.next() == Some(':') && after.next() != Some(':');
        Literal { line, text, key }
    }

    /// Steps over one character, counting lines.
    fn bump(&mut self) {
        if self.peek(0) == Some('\n') {
            self.line += 1;
        }
        self.at += 1;
    }

    /// The rest of a literal whose opening quote was just passed, closed by
    /// `"` and `hashes` `#`; escapes are read in one that is not `raw`.
    fn quoted(&mut self, hashes: usize, raw: bool) -> String {
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if c == '"' && (1..=hashes).all(|n| self.peek(n) == Some('#')) {
                self.at += 1 + hashes;
                break;
            }
            if c == '\\' && !raw {
                self.at += 1;
                match self.peek(0) {
                    Some('"') => text.push('"'),
                    Some(other) => {
                        text.push('\\');
                        text.push(other);
                    }
                    None => break,
                }
                self.bump();
                continue;
            }
            text.push(c);
            self.bump();
        }
        text
    }

    /// `'x'`, `'\n'`, `'"'` skipped whole; a lifetime's quote only.
    fn char_or_lifetime(&mut self) {
        if self.peek(1) == Some('\\') {
            self.at += 3;
            while self.peek(0).is_some_and(|c| c != '\'') {
                self.at += 1;
            }
            self.at += 1;
        } else if self.peek(2) == Some('\'') {
            self.at += 3;
        } else {
            self.at += 1;
        }
    }
}

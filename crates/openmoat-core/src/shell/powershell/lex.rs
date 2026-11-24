//! PowerShell's tokens, as far as the reader goes (`powershell.rs`).
//!
//! Quotes: `'…'` is literal (`''` is one `'`); `"…"` expands `$name`,
//! `${name}`, `$env:NAME` and `$( … )`, and `` ` `` escapes the next
//! character. Outside quotes `` ` `` escapes the next character too, and at
//! the end of a line continues it. `#` starts a comment where a word may
//! start, `<# … #>` is a block comment. Statements end at `;`, a line break,
//! `&&` and `||`; `|` joins a pipeline. `( ) { } [ ] @( @{ ,` and an `=`
//! between words make the statement one the reader does not read
//! ([`Tok::Complex`]), except `$name = …` and `$env:NAME = …` at its start.

/// One part of a word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Part {
    /// Text, quoted or not.
    Lit(String),
    /// `$env:NAME`.
    Env(String),
    /// `$name`, `${name}`: a PowerShell variable, lowercase.
    Var(String),
    /// `$( … )` in a double-quoted string: code that runs.
    Sub(String),
}

/// One word: its parts, and whether any part was quoted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct PsWord {
    pub(super) parts: Vec<Part>,
    pub(super) quoted: bool,
    /// Its first character was unquoted `~`.
    pub(super) tilde: bool,
}

impl PsWord {
    /// The word's text when it is all literal.
    pub(super) fn literal(&self) -> Option<String> {
        self.parts
            .iter()
            .map(|p| match p {
                Part::Lit(s) => Some(s.as_str()),
                _ => None,
            })
            .collect::<Option<Vec<&str>>>()
            .map(|v| v.concat())
    }

    /// The word's text with every expansion written as PowerShell shows it.
    pub(super) fn display(&self) -> String {
        self.parts
            .iter()
            .map(|p| match p {
                Part::Lit(s) => s.clone(),
                Part::Env(n) => format!("$env:{n}"),
                Part::Var(n) => format!("${n}"),
                Part::Sub(s) => format!("$({s})"),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Tok {
    Word(PsWord),
    /// `|`.
    Pipe,
    /// `;`, a line break, `&&`, `||`.
    End(&'static str),
    /// `>`, `>>`, `2>`, `*>`…: the redirection and its target.
    Redirect(&'static str),
    /// `&` where a command starts: the call operator.
    Call,
    /// `=` after the first word of a statement.
    Assign,
    /// Syntax the reader does not read; the character.
    Complex(char),
}

/// Why a line cannot be tokenised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LexError {
    /// A `'…'` string that does not end.
    Single,
    /// A `"…"` string that does not end.
    Double,
    /// A `<# … #>` comment that does not end.
    Comment,
}

struct Lexer {
    chars: Vec<char>,
    at: usize,
    out: Vec<Tok>,
    word: PsWord,
    in_word: bool,
}

/// The tokens of `line`.
pub(super) fn lex(line: &str) -> Result<Vec<Tok>, LexError> {
    let mut lx = Lexer {
        chars: line.chars().collect(),
        at: 0,
        out: Vec::new(),
        word: PsWord::default(),
        in_word: false,
    };
    lx.run()?;
    Ok(lx.out)
}

impl Lexer {
    fn peek(&self, n: usize) -> Option<char> {
        self.chars.get(self.at + n).copied()
    }

    fn lit(&mut self, c: char) {
        self.in_word = true;
        if let Some(Part::Lit(s)) = self.word.parts.last_mut() {
            s.push(c);
        } else {
            self.word.parts.push(Part::Lit(c.to_string()));
        }
    }

    fn flush(&mut self) {
        if self.in_word {
            self.out.push(Tok::Word(std::mem::take(&mut self.word)));
        }
        self.in_word = false;
    }

    fn push(&mut self, tok: Tok) {
        self.flush();
        self.out.push(tok);
    }

    fn run(&mut self) -> Result<(), LexError> {
        while let Some(c) = self.peek(0) {
            self.at += 1;
            match c {
                '`' => match self.peek(0) {
                    Some('\n') => self.at += 1,
                    Some('\r') if self.peek(1) == Some('\n') => self.at += 2,
                    Some(next) => {
                        self.at += 1;
                        self.lit(next);
                    }
                    None => {}
                },
                '\'' => self.single()?,
                '"' => self.double()?,
                '$' => self.dollar(false),
                '#' if !self.in_word => self.skip_comment(),
                '<' if self.peek(0) == Some('#') => self.block_comment()?,
                '|' if self.peek(0) == Some('|') => {
                    self.at += 1;
                    self.push(Tok::End("||"));
                }
                '|' => self.push(Tok::Pipe),
                '&' if self.peek(0) == Some('&') => {
                    self.at += 1;
                    self.push(Tok::End("&&"));
                }
                '&' if !self.in_word && self.command_starts() => self.push(Tok::Call),
                ';' | '\n' => self.push(Tok::End(";")),
                '\r' => {}
                '>' => self.redirect(c),
                '2' | '3' | '4' | '5' | '6' | '*' if !self.in_word && self.peek(0) == Some('>') => {
                    self.redirect(c);
                }
                '=' if !self.in_word => self.push(Tok::Assign),
                // `file[1].txt` is a name; any other bracket, a parenthesis, a
                // brace, an array's comma or `<` is syntax the reader leaves
                '[' | ']' if self.in_word => self.lit(c),
                '(' | ')' | '{' | '}' | '[' | ']' | ',' | '<' => self.push(Tok::Complex(c)),
                '@' if !self.in_word && matches!(self.peek(0), Some('(' | '{')) => {
                    self.push(Tok::Complex(c));
                }
                c if c.is_whitespace() => self.flush(),
                c => {
                    if !self.in_word && c == '~' {
                        self.word.tilde = true;
                    }
                    self.lit(c);
                }
            }
        }
        self.flush();
        Ok(())
    }

    /// Whether the token before is the end of a statement or a pipe.
    fn command_starts(&self) -> bool {
        matches!(self.out.last(), None | Some(Tok::End(_) | Tok::Pipe))
    }

    fn single(&mut self) -> Result<(), LexError> {
        self.in_word = true;
        self.word.quoted = true;
        if !matches!(self.word.parts.last(), Some(Part::Lit(_))) {
            self.word.parts.push(Part::Lit(String::new()));
        }
        loop {
            match self.peek(0) {
                None => return Err(LexError::Single),
                Some('\'') if self.peek(1) == Some('\'') => {
                    self.at += 2;
                    self.lit('\'');
                }
                Some('\'') => {
                    self.at += 1;
                    return Ok(());
                }
                Some(c) => {
                    self.at += 1;
                    self.lit(c);
                }
            }
        }
    }

    fn double(&mut self) -> Result<(), LexError> {
        self.in_word = true;
        self.word.quoted = true;
        if !matches!(self.word.parts.last(), Some(Part::Lit(_))) {
            self.word.parts.push(Part::Lit(String::new()));
        }
        loop {
            match self.peek(0) {
                None => return Err(LexError::Double),
                Some('"') if self.peek(1) == Some('"') => {
                    self.at += 2;
                    self.lit('"');
                }
                Some('"') => {
                    self.at += 1;
                    return Ok(());
                }
                Some('`') => {
                    self.at += 1;
                    if let Some(next) = self.peek(0) {
                        self.at += 1;
                        self.lit(escaped(next));
                    }
                }
                Some('$') => {
                    self.at += 1;
                    self.dollar(true);
                }
                Some(c) => {
                    self.at += 1;
                    self.lit(c);
                }
            }
        }
    }

    /// After a `$`: a variable, `$env:NAME`, `${name}`, or `$( … )`.
    fn dollar(&mut self, quoted: bool) {
        match self.peek(0) {
            Some('(') if quoted => {
                self.in_word = true;
                let start = self.at + 1;
                let mut depth = 0usize;
                while let Some(c) = self.peek(0) {
                    self.at += 1;
                    match c {
                        '(' => depth += 1,
                        ')' if depth <= 1 => break,
                        ')' => depth -= 1,
                        _ => {}
                    }
                }
                let end = self.at.saturating_sub(1).max(start);
                let inner: String = self.chars[start.min(end)..end].iter().collect();
                self.word.parts.push(Part::Sub(inner));
            }
            Some('(') => self.push(Tok::Complex('$')),
            Some('{') => {
                let start = self.at + 1;
                let len = self.chars[start..]
                    .iter()
                    .take_while(|c| **c != '}')
                    .count();
                let name: String = self.chars[start..start + len].iter().collect();
                self.at = start + len + 1;
                self.variable(&name);
            }
            Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '?' => {
                let start = self.at;
                let len = self.chars[start..]
                    .iter()
                    .take_while(|c| {
                        c.is_ascii_alphanumeric() || **c == '_' || **c == ':' || **c == '?'
                    })
                    .count();
                let name: String = self.chars[start..start + len].iter().collect();
                self.at = start + len;
                self.variable(name.trim_end_matches(':'));
            }
            _ => self.lit('$'),
        }
    }

    fn variable(&mut self, name: &str) {
        self.in_word = true;
        let lower = name.to_ascii_lowercase();
        let part = match lower.strip_prefix("env:") {
            Some(_) => Part::Env(name[4..].to_ascii_uppercase()),
            None => Part::Var(lower),
        };
        self.word.parts.push(part);
    }

    fn redirect(&mut self, first: char) {
        let mut op = String::from(first);
        while let Some(c) = self.peek(0) {
            if c == '>' || c == '&' || c.is_ascii_digit() {
                op.push(c);
                self.at += 1;
            } else {
                break;
            }
        }
        let kind: &'static str = match op.as_str() {
            "<" => "<",
            ">" | "1>" => ">",
            ">>" | "1>>" => ">>",
            o if o.ends_with(">&1") || o.ends_with(">&2") => "dup",
            o if o.ends_with(">>") => ">>",
            _ => ">",
        };
        self.push(Tok::Redirect(kind));
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek(0) {
            if c == '\n' {
                break;
            }
            self.at += 1;
        }
    }

    fn block_comment(&mut self) -> Result<(), LexError> {
        self.at += 1;
        while self.at < self.chars.len() {
            if self.peek(0) == Some('#') && self.peek(1) == Some('>') {
                self.at += 2;
                return Ok(());
            }
            self.at += 1;
        }
        Err(LexError::Comment)
    }
}

/// The character `` `c `` stands for in a double-quoted string.
fn escaped(c: char) -> char {
    match c {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        '0' => '\0',
        other => other,
    }
}

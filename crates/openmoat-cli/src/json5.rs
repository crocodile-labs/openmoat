//! Reading JSON5 (<https://spec.json5.org/>), the format OpenClaw reads its
//! `openclaw.json` in (<https://docs.openclaw.ai/gateway/configuration>).
//!
//! OpenMoat reads JSON5 into a [`Value`] and never writes it: a caller that
//! edits a file writes plain JSON, which JSON5 readers read too. Comments have
//! no place in a [`Value`], so [`Parsed::comments`] says whether writing the
//! file back would drop some; callers then refuse. `Infinity` and `NaN` have no
//! JSON form and are refused. Duplicate keys keep the last value, as
//! JavaScript objects do. No dependency: the grammar is small, and a parser
//! here keeps reading in step with what the lock and the MCP pins see.

use anyhow::{Result, bail};
use serde_json::{Map, Number, Value};

/// Nesting deeper than this is refused rather than recursed into.
const MAX_DEPTH: usize = 128;

/// A JSON5 document read as JSON.
#[derive(Debug)]
pub struct Parsed {
    pub value: Value,
    /// Whether the text has a `//` or `/* */` comment.
    pub comments: bool,
}

/// Read `text` as one JSON5 value.
pub fn parse(text: &str) -> Result<Parsed> {
    let mut parser = Parser {
        chars: text.chars().collect(),
        pos: 0,
        comments: false,
    };
    parser.skip()?;
    let value = parser.value(0)?;
    parser.skip()?;
    if parser.pos < parser.chars.len() {
        bail!("{}: text after the end of the value", parser.at());
    }
    Ok(Parsed {
        value,
        comments: parser.comments,
    })
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    comments: bool,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.pos + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    /// `line:column` of the current position, for messages.
    fn at(&self) -> String {
        let before = &self.chars[..self.pos.min(self.chars.len())];
        let line = before.iter().filter(|c| **c == '\n').count() + 1;
        let column = before.iter().rev().take_while(|c| **c != '\n').count() + 1;
        format!("line {line}, column {column}")
    }

    /// Skip white space and comments.
    fn skip(&mut self) -> Result<()> {
        loop {
            match (self.peek(), self.peek_at(1)) {
                (Some(c), _) if is_space(c) => self.pos += 1,
                (Some('/'), Some('/')) => {
                    self.comments = true;
                    while self.peek().is_some_and(|c| !is_line_end(c)) {
                        self.pos += 1;
                    }
                }
                (Some('/'), Some('*')) => {
                    self.comments = true;
                    self.pos += 2;
                    loop {
                        match self.bump() {
                            None => bail!("a `/*` comment is not closed"),
                            Some('*') if self.peek() == Some('/') => {
                                self.pos += 1;
                                break;
                            }
                            Some(_) => {}
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            bail!("{}: nested more than {MAX_DEPTH} levels deep", self.at());
        }
        match self.peek() {
            None => bail!("the text ends where a value should be"),
            Some('{') => self.object(depth),
            Some('[') => self.array(depth),
            Some(quote @ ('"' | '\'')) => {
                self.pos += 1;
                Ok(Value::String(self.string(quote)?))
            }
            Some(c) if c == '-' || c == '+' || c == '.' || c.is_ascii_digit() => self.number(),
            Some(c) if is_id_start(c) => {
                let at = self.at();
                match self.identifier()?.as_str() {
                    "null" => Ok(Value::Null),
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    word @ ("Infinity" | "NaN") => bail!("{at}: `{word}` has no JSON form"),
                    word => bail!("{at}: `{word}` is not a value"),
                }
            }
            Some(c) => bail!("{}: `{c}` cannot start a value", self.at()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value> {
        self.pos += 1;
        let mut map = Map::new();
        loop {
            self.skip()?;
            if self.peek() == Some('}') {
                self.pos += 1;
                return Ok(Value::Object(map));
            }
            let key = match self.peek() {
                Some(quote @ ('"' | '\'')) => {
                    self.pos += 1;
                    self.string(quote)?
                }
                Some(c) if is_id_start(c) || c == '\\' => self.identifier()?,
                _ => bail!("{}: expected a key", self.at()),
            };
            self.skip()?;
            if self.bump() != Some(':') {
                bail!("{}: expected `:` after key `{key}`", self.at());
            }
            self.skip()?;
            let value = self.value(depth + 1)?;
            map.insert(key, value);
            self.skip()?;
            match self.bump() {
                Some(',') => {}
                Some('}') => return Ok(Value::Object(map)),
                _ => bail!("{}: expected `,` or `}}`", self.at()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value> {
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip()?;
            if self.peek() == Some(']') {
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            items.push(self.value(depth + 1)?);
            self.skip()?;
            match self.bump() {
                Some(',') => {}
                Some(']') => return Ok(Value::Array(items)),
                _ => bail!("{}: expected `,` or `]`", self.at()),
            }
        }
    }

    /// A string after its opening `quote`.
    fn string(&mut self, quote: char) -> Result<String> {
        let mut out = String::new();
        loop {
            match self.bump() {
                None => bail!("a string is not closed"),
                Some(c) if c == quote => return Ok(out),
                Some('\\') => self.escape(&mut out)?,
                Some('\n' | '\r') => bail!("{}: a line break inside a string", self.at()),
                Some(c) => out.push(c),
            }
        }
    }

    /// One escape after its `\`, appended to `out`.
    fn escape(&mut self, out: &mut String) -> Result<()> {
        let at = self.at();
        match self.bump() {
            None => bail!("a string is not closed"),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('v') => out.push('\u{b}'),
            Some('0') if !self.peek().is_some_and(|c| c.is_ascii_digit()) => out.push('\0'),
            Some(c @ '0'..='9') => bail!("{at}: `\\{c}` is not an escape"),
            Some('x') => {
                let code = self.hex(2)?;
                out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
            }
            Some('u') => out.push(self.unicode()?),
            // A line continuation: the escaped line break is left out.
            Some('\r') => {
                if self.peek() == Some('\n') {
                    self.pos += 1;
                }
            }
            Some('\n' | '\u{2028}' | '\u{2029}') => {}
            Some(c) => out.push(c),
        }
        Ok(())
    }

    /// The character of a `\u` escape (its `u` already read), a surrogate pair
    /// joined.
    fn unicode(&mut self) -> Result<char> {
        let at = self.at();
        let high = self.hex(4)?;
        if !(0xD800..0xDC00).contains(&high) {
            return char::from_u32(high).ok_or_else(|| lone(&at));
        }
        if self.bump() != Some('\\') || self.bump() != Some('u') {
            return Err(lone(&at));
        }
        let low = self.hex(4)?;
        if !(0xDC00..0xE000).contains(&low) {
            return Err(lone(&at));
        }
        char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)).ok_or_else(|| lone(&at))
    }

    fn hex(&mut self, digits: usize) -> Result<u32> {
        let mut code = 0;
        for _ in 0..digits {
            match self.bump().and_then(|c| c.to_digit(16)) {
                Some(d) => code = code * 16 + d,
                None => bail!("{}: expected {digits} hexadecimal digits", self.at()),
            }
        }
        Ok(code)
    }

    /// An unquoted key or keyword: letters, `$`, `_`, digits after the first,
    /// and `\u` escapes.
    fn identifier(&mut self) -> Result<String> {
        let mut out = String::new();
        loop {
            match self.peek() {
                Some('\\') => {
                    self.pos += 1;
                    if self.bump() != Some('u') {
                        bail!("{}: only `\\u` escapes may appear in a key", self.at());
                    }
                    out.push(self.unicode()?);
                }
                Some(c) if is_id_start(c) || (!out.is_empty() && is_id_part(c)) => {
                    self.pos += 1;
                    out.push(c);
                }
                _ => break,
            }
        }
        if out.is_empty() {
            bail!("{}: expected a key", self.at());
        }
        Ok(out)
    }

    fn number(&mut self) -> Result<Value> {
        let at = self.at();
        let mut text = String::new();
        match self.peek() {
            Some('-') => {
                text.push('-');
                self.pos += 1;
            }
            Some('+') => self.pos += 1,
            _ => {}
        }
        if self.peek().is_some_and(is_id_start) {
            let word = self.identifier()?;
            bail!("{at}: `{word}` has no JSON form or is not a number");
        }
        let hex = self.peek() == Some('0') && matches!(self.peek_at(1), Some('x' | 'X'));
        let number = if hex {
            self.pos += 2;
            self.hex_number(&text, &at)?
        } else {
            self.decimal(text, &at)?
        };
        if self.peek().is_some_and(is_id_part) {
            bail!("{at}: a number runs into other text");
        }
        Ok(Value::Number(number))
    }

    fn hex_number(&mut self, sign: &str, at: &str) -> Result<Number> {
        let start = self.pos;
        let mut value: u64 = 0;
        while let Some(d) = self.peek().and_then(|c| c.to_digit(16)) {
            self.pos += 1;
            value = value
                .checked_mul(16)
                .and_then(|v| v.checked_add(u64::from(d)))
                .ok_or_else(|| anyhow::Error::msg(format!("{at}: number too large")))?;
        }
        if self.pos == start {
            bail!("{at}: `0x` without digits");
        }
        if sign.is_empty() {
            return Ok(Number::from(value));
        }
        let negative = i64::try_from(value)
            .ok()
            .and_then(i64::checked_neg)
            .ok_or_else(|| anyhow::Error::msg(format!("{at}: number too large")))?;
        Ok(Number::from(negative))
    }

    /// Digits with an optional fraction and exponent; JSON5 allows `.5` and
    /// `5.`, which are written out as `0.5` and `5.0` for JSON.
    fn decimal(&mut self, mut text: String, at: &str) -> Result<Number> {
        let int = self.digits();
        if int.len() > 1 && int.starts_with('0') {
            bail!("{at}: a number with a leading zero");
        }
        let fraction = if self.peek() == Some('.') {
            self.pos += 1;
            Some(self.digits())
        } else {
            None
        };
        if int.is_empty() && fraction.as_deref().is_none_or(str::is_empty) {
            bail!("{at}: a number without digits");
        }
        text.push_str(if int.is_empty() { "0" } else { &int });
        if let Some(fraction) = fraction {
            text.push('.');
            text.push_str(if fraction.is_empty() { "0" } else { &fraction });
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.pos += 1;
            text.push('e');
            if let Some(sign @ ('+' | '-')) = self.peek() {
                self.pos += 1;
                text.push(sign);
            }
            let exponent = self.digits();
            if exponent.is_empty() {
                bail!("{at}: an exponent without digits");
            }
            text.push_str(&exponent);
        }
        text.parse::<Number>()
            .map_err(|e| anyhow::Error::msg(format!("{at}: {e}")))
    }

    fn digits(&mut self) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek().filter(char::is_ascii_digit) {
            self.pos += 1;
            out.push(c);
        }
        out
    }
}

fn lone(at: &str) -> anyhow::Error {
    anyhow::Error::msg(format!("{at}: a `\\u` escape names half a character"))
}

/// JSON5 white space and line breaks; the byte order mark counts as space.
fn is_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

fn is_line_end(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

fn is_id_start(c: char) -> bool {
    c.is_alphabetic() || c == '$' || c == '_'
}

fn is_id_part(c: char) -> bool {
    is_id_start(c) || c.is_alphanumeric() || c == '\u{200c}' || c == '\u{200d}'
}

#[cfg(test)]
mod tests;

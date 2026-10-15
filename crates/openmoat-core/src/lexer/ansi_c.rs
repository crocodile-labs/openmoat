//! `$'…'` (ANSI-C quoting): the escapes bash decodes inside it.

use super::{LexError, Lexer};

impl Lexer {
    /// The inside of `$'…'`, decoded the way bash does (`\x2f` is `/`, `\'` a
    /// quote). The shell expands the result no further, but it is not marked
    /// literal: a `$` in it is still read as a variable, stricter, never looser.
    pub(super) fn ansi_c_quoted(&mut self) -> Result<(), LexError> {
        let mut bytes = Vec::new();
        loop {
            match self.bump() {
                Some('\'') => break,
                Some('\\') => self.ansi_c_escape(&mut bytes)?,
                Some(c) => bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
                None => return Err(LexError::UnterminatedSingleQuote),
            }
        }
        if bytes.contains(&0) {
            return Err(LexError::AnsiC);
        }
        let text = String::from_utf8(bytes).map_err(|_| LexError::AnsiC)?;
        let word = self.word();
        word.quoted = true;
        word.text.push_str(&text);
        Ok(())
    }

    /// One escape of `$'…'`, after its backslash.
    fn ansi_c_escape(&mut self, out: &mut Vec<u8>) -> Result<(), LexError> {
        let Some(c) = self.bump() else {
            return Err(LexError::UnterminatedSingleQuote);
        };
        let byte = match c {
            'a' => 0x07,
            'b' => 0x08,
            'e' | 'E' => 0x1b,
            'f' => 0x0c,
            'n' => b'\n',
            'r' => b'\r',
            't' => b'\t',
            'v' => 0x0b,
            '\\' | '\'' | '"' | '?' => c as u8,
            '0'..='7' => {
                let mut value = c.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match self.peek().and_then(|d| d.to_digit(8)) {
                        Some(d) => {
                            self.bump();
                            value = value * 8 + d;
                        }
                        None => break,
                    }
                }
                (value & 0xff) as u8
            }
            'x' => {
                // two hex digits at most, so the value is a byte
                let Some(byte) = self.hex_digits(2).and_then(|v| u8::try_from(v).ok()) else {
                    out.extend_from_slice(b"\\x");
                    return Ok(());
                };
                byte
            }
            'u' | 'U' => {
                let max = if c == 'u' { 4 } else { 8 };
                let Some(value) = self.hex_digits(max) else {
                    out.push(b'\\');
                    out.push(c as u8);
                    return Ok(());
                };
                let decoded = char::from_u32(value).ok_or(LexError::AnsiC)?;
                out.extend_from_slice(decoded.encode_utf8(&mut [0; 4]).as_bytes());
                return Ok(());
            }
            'c' => match self.bump() {
                Some('?') => 0x7f,
                Some(x) if x.is_ascii() && x != '\\' => (x as u8) & 0x1f,
                _ => return Err(LexError::AnsiC),
            },
            other => {
                out.push(b'\\');
                out.extend_from_slice(other.encode_utf8(&mut [0; 4]).as_bytes());
                return Ok(());
            }
        };
        out.push(byte);
        Ok(())
    }

    /// Up to `max` hex digits, if there is one at least.
    fn hex_digits(&mut self, max: usize) -> Option<u32> {
        let mut value = None;
        for _ in 0..max {
            let Some(d) = self.peek().and_then(|d| d.to_digit(16)) else {
                break;
            };
            self.bump();
            value = Some(value.unwrap_or(0) * 16 + d);
        }
        value
    }
}

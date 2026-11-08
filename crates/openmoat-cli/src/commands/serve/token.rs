//! The token of one `openmoat serve` run: 32 random bytes as hex, made at
//! start, printed once in the link, held only in memory.

use std::fmt;

use anyhow::{Context as _, Result};
use openmoat_proxy::constant_time_eq;
use zeroize::Zeroizing;

/// Bytes of randomness in a token.
const BYTES: usize = 32;

pub struct Token(Zeroizing<String>);

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// A new token from the operating system's random source.
    pub fn generate() -> Result<Self> {
        let mut raw = Zeroizing::new([0u8; BYTES]);
        getrandom::fill(raw.as_mut_slice())
            .map_err(|e| anyhow::Error::msg(e.to_string()))
            .context("reading random bytes for the serve token")?;
        Ok(Self::from_bytes(raw.as_slice()))
    }

    fn from_bytes(raw: &[u8]) -> Self {
        let mut text = Zeroizing::new(String::with_capacity(raw.len() * 2));
        for byte in raw {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
        Self(text)
    }

    /// The token as the link carries it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `given` is this token, compared in time that depends only on
    /// the lengths.
    pub fn matches(&self, given: &str) -> bool {
        constant_time_eq(self.0.as_bytes(), given.as_bytes())
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
impl Token {
    /// A token of known bytes, for tests.
    pub fn fixed(raw: &[u8]) -> Self {
        Self::from_bytes(raw)
    }
}

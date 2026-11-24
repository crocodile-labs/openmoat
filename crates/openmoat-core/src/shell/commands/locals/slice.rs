//! `${name:offset}` and `${name:offset:length}`: the shell cuts the value
//! (ADR-116). Bashfuscator and hand-written evasions spell a command out of a
//! longer string (`s=QZcatZQ; ${s:2:3} ~/.ssh/id_rsa`); for a variable whose
//! every value is known (`locals.rs`), the cut is known too.
//!
//! Only literal integers are read: `${s:2}`, `${s:2:3}`, `${s: -3}`,
//! `${s:(-3):2}`, `${s:1:-1}`. An offset that is an expression (`${s:i}`,
//! `${s:1+1}`) is not, and the use stays unknown. `${s:-x}`, `${s:=x}`,
//! `${s:+x}` and `${s:?x}` are other expansions, not cuts.

/// One cut, as written after the variable's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Slice {
    offset: i64,
    length: Option<i64>,
}

impl Slice {
    /// The cut at the start of `after`, the text that follows `${name`, and
    /// the bytes it takes up to and including the closing `}`.
    pub(super) fn parse(after: &str) -> Option<(Self, usize)> {
        let body = after.strip_prefix(':')?;
        if body.starts_with(['-', '=', '+', '?']) {
            return None;
        }
        let end = body.find('}')?;
        let mut parts = body[..end].splitn(2, ':');
        let offset = number(parts.next()?)?;
        let length = match parts.next() {
            Some(text) => Some(number(text)?),
            None => None,
        };
        Some((Self { offset, length }, end + 2))
    }

    /// `value` cut as bash cuts it; `None` where bash reports an error (a
    /// negative length that ends before the offset).
    pub(super) fn apply(self, value: &str) -> Option<String> {
        let chars: Vec<char> = value.chars().collect();
        let n = i64::try_from(chars.len()).ok()?;
        let start = if self.offset < 0 {
            (n + self.offset).max(0)
        } else {
            self.offset.min(n)
        };
        let end = match self.length {
            None => n,
            Some(len) if len >= 0 => (start + len).min(n),
            Some(len) => {
                let end = n + len;
                if end < start {
                    return None;
                }
                end
            }
        };
        let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
        Some(chars[start..end].iter().collect())
    }
}

/// A literal integer: digits after an optional `-`, with spaces around and
/// optionally in parentheses (`(-3)`).
fn number(text: &str) -> Option<i64> {
    let text = text.trim();
    let text = text
        .strip_prefix('(')
        .and_then(|t| t.strip_suffix(')'))
        .map_or(text, str::trim);
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::Slice;

    fn cut(expansion: &str, value: &str) -> Option<String> {
        let (slice, used) = Slice::parse(expansion)?;
        assert_eq!(used, expansion.len());
        slice.apply(value)
    }

    #[test]
    fn cuts_as_bash_does() {
        assert_eq!(cut(":2:3}", "QZcatZQ").as_deref(), Some("cat"));
        assert_eq!(cut(":2}", "QZcat").as_deref(), Some("cat"));
        assert_eq!(cut(": -3}", "QZcat").as_deref(), Some("cat"));
        assert_eq!(cut(":(-5):3}", "QZcat").as_deref(), Some("QZc"));
        assert_eq!(cut(":1:-1}", "xcatx").as_deref(), Some("cat"));
        assert_eq!(cut(":9}", "cat").as_deref(), Some(""));
        assert_eq!(cut(":2:-5}", "cat"), None);
    }

    #[test]
    fn other_expansions_are_not_cuts() {
        for after in [":-x}", ":=x}", ":+x}", ":?x}", ":i}", ":1+1}", ":}", ":2"] {
            assert_eq!(Slice::parse(after), None, "{after}");
        }
    }
}

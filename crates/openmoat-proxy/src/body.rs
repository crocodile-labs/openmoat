//! Where a plain-HTTP request's body ends.
//!
//! The proxy decides one request per connection: the head it read. Whatever
//! the client sends after that request's body (a pipelined second request,
//! possibly for another host) is not forwarded. The upstream head carries
//! `Connection: close`, so a well-behaved server would ignore those bytes, but
//! the proxy does not rely on the server for that (RFC 9112 §9.3.2).
//!
//! The body's end follows the framing `request::check_framing` already made
//! unambiguous: no body, `Content-Length`, or `Transfer-Encoding: chunked`.

/// How the request's body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// Neither `Content-Length` nor `Transfer-Encoding`: no body (RFC 9112 §6.3).
    None,
    /// `Content-Length: n`.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// The framing of the head the proxy forwards. The head was parsed and its
/// framing checked already; anything unexpected here reads as no body, so
/// nothing after the head is forwarded.
pub(crate) fn framing(head: &[u8]) -> Framing {
    let mut headers = [httparse::EMPTY_HEADER; crate::request::MAX_HEADERS + 2];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(head), Ok(httparse::Status::Complete(_))) {
        return Framing::None;
    }
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            return Framing::Chunked;
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            return std::str::from_utf8(h.value)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .map_or(Framing::None, Framing::Length);
        }
    }
    Framing::None
}

/// Chunked framing the proxy will not follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// Longest chunk-size line (size, extensions) or trailer line, in bytes.
const MAX_LINE: usize = 8 * 1024;

/// Largest chunk size the proxy follows: 2^31 - 1. Servers that hold the size
/// in a signed 32-bit integer read a larger one as another number, and would
/// see a different body end.
const MAX_CHUNK: u64 = (1 << 31) - 1;

/// Follows a body as its bytes go by and says how many of them belong to it.
#[derive(Debug)]
pub(crate) struct BodyEnd {
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Bytes of a `Content-Length` body still to come.
    Length(u64),
    /// In a chunk-size line: the size so far, hex digits read, line length,
    /// and which part of the line this is.
    Size {
        size: u64,
        digits: usize,
        len: usize,
        part: Part,
    },
    /// After the chunk-size line's `\r`.
    SizeLf {
        size: u64,
    },
    /// Bytes of chunk data still to come.
    Data(u64),
    /// After chunk data: `\r`, then `\n`.
    DataCr,
    DataLf,
    /// In a trailer line (after the last chunk), with its length so far.
    Trailer {
        len: usize,
    },
    /// After a trailer line's `\r`; `empty` when the line was the final blank one.
    TrailerLf {
        empty: bool,
    },
    /// The body is complete.
    Done,
}

/// The parts of a chunk-size line: `1*HEXDIG BWS [ ";" chunk-ext ] CRLF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// The hex size.
    Digits,
    /// Spaces or tabs after the size: only `;` or the line's end may follow.
    Space,
    /// After `;`: extensions, kept as they are, until the line's end.
    Extension,
}

const SIZE_START: State = State::Size {
    size: 0,
    digits: 0,
    len: 0,
    part: Part::Digits,
};

impl BodyEnd {
    pub(crate) fn new(framing: Framing) -> Self {
        let state = match framing {
            Framing::None | Framing::Length(0) => State::Done,
            Framing::Length(n) => State::Length(n),
            Framing::Chunked => SIZE_START,
        };
        Self { state }
    }

    /// Whether the whole body has gone by.
    pub(crate) fn done(&self) -> bool {
        self.state == State::Done
    }

    /// Take the next `bytes` of the stream; returns how many of them, from the
    /// start, belong to the body. Fewer than `bytes.len()` means the body
    /// ended inside them.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<usize, Malformed> {
        let mut at = 0;
        while at < bytes.len() && !self.done() {
            at += self.step(&bytes[at..])?;
        }
        Ok(at)
    }

    /// Consume from the start of `bytes` (never empty); returns how many.
    fn step(&mut self, bytes: &[u8]) -> Result<usize, Malformed> {
        let available = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        match self.state {
            State::Length(left) | State::Data(left) => {
                let take = left.min(available);
                let rest = left - take;
                self.state = match (self.state, rest) {
                    (State::Length(_), 0) => State::Done,
                    (State::Length(_), _) => State::Length(rest),
                    (_, 0) => State::DataCr,
                    _ => State::Data(rest),
                };
                // `take` is at most `bytes.len()`, so it fits.
                Ok(usize::try_from(take).unwrap_or(bytes.len()))
            }
            _ => {
                self.byte(bytes[0])?;
                Ok(1)
            }
        }
    }

    fn byte(&mut self, b: u8) -> Result<(), Malformed> {
        self.state = match self.state {
            State::Size {
                size,
                digits,
                len,
                part,
            } => size_line(size, digits, len, part, b)?,
            State::SizeLf { size } if b == b'\n' => {
                if size == 0 {
                    State::Trailer { len: 0 }
                } else {
                    State::Data(size)
                }
            }
            State::DataCr if b == b'\r' => State::DataLf,
            State::DataLf if b == b'\n' => SIZE_START,
            State::Trailer { len } if b == b'\r' => State::TrailerLf { empty: len == 0 },
            State::Trailer { len } if len < MAX_LINE && b != b'\n' => {
                State::Trailer { len: len + 1 }
            }
            State::TrailerLf { empty: true } if b == b'\n' => State::Done,
            State::TrailerLf { empty: false } if b == b'\n' => State::Trailer { len: 0 },
            _ => return Err(Malformed),
        };
        Ok(())
    }
}

/// One byte of a chunk-size line: `1*HEXDIG BWS [ ";" chunk-ext ] CRLF`
/// (RFC 9112 §7.1). Anything else, such as a second number after a space,
/// is malformed: a server reading it differently must not see other bytes.
fn size_line(size: u64, digits: usize, len: usize, part: Part, b: u8) -> Result<State, Malformed> {
    if len >= MAX_LINE {
        return Err(Malformed);
    }
    let next = |size, digits, part| State::Size {
        size,
        digits,
        len: len + 1,
        part,
    };
    match (part, b) {
        (_, b'\r') if digits > 0 => Ok(State::SizeLf { size }),
        (_, b'\r' | b'\n') => Err(Malformed),
        (Part::Extension, _) => Ok(next(size, digits, Part::Extension)),
        (Part::Digits | Part::Space, b';') if digits > 0 => Ok(next(size, digits, Part::Extension)),
        (Part::Digits | Part::Space, b' ' | b'\t') if digits > 0 => {
            Ok(next(size, digits, Part::Space))
        }
        (Part::Digits, _) => {
            let digit = char::from(b).to_digit(16).ok_or(Malformed)?;
            let size = size
                .checked_mul(16)
                .and_then(|s| s.checked_add(u64::from(digit)))
                .filter(|s| *s <= MAX_CHUNK)
                .ok_or(Malformed)?;
            Ok(next(size, digits + 1, Part::Digits))
        }
        (Part::Space, _) => Err(Malformed),
    }
}

#[cfg(test)]
mod tests;

//! The body of an accepted answer, read whole or not at all, at most
//! [`MAX_BODY`] bytes: an OTLP collector says in it that it took a request
//! only in part (`partial_success`), which its status does not.

use std::io::Read;

/// The most bytes of an answer's body read; a longer one is not read.
pub const MAX_BODY: usize = 64 * 1024;

/// How the answer says where its body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Framing {
    /// No body (`204`, `304`).
    Empty,
    /// `Content-Length`.
    Length(usize),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Neither: the body ends when the connection closes.
    Close,
}

/// The body after the head, `read` holding what came with it: `None` when it
/// is longer than [`MAX_BODY`], cut off, badly chunked or not read in time.
pub(super) fn read(stream: &mut impl Read, mut raw: Vec<u8>, framing: Framing) -> Option<Vec<u8>> {
    // The chunk lines and their line ends take room besides the body.
    let limit = match framing {
        Framing::Empty => return Some(Vec::new()),
        Framing::Length(n) if n > MAX_BODY => return None,
        Framing::Length(n) => n,
        Framing::Chunked => 2 * MAX_BODY,
        Framing::Close => MAX_BODY,
    };
    let mut chunk = [0u8; 4096];
    loop {
        match framing {
            Framing::Length(n) if raw.len() >= n => {
                raw.truncate(n);
                return Some(raw);
            }
            Framing::Chunked => match dechunk(&raw) {
                Chunks::Done(body) if body.len() <= MAX_BODY => return Some(body),
                Chunks::Done(_) | Chunks::Bad => return None,
                Chunks::More => {}
            },
            _ => {}
        }
        if raw.len() > limit {
            return None;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            // Only a body that ends with the connection may end here.
            return (framing == Framing::Close).then_some(raw);
        }
        raw.extend_from_slice(&chunk[..n]);
    }
}

/// What a chunked body read so far holds.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Chunks {
    /// Every chunk up to the last, empty one.
    Done(Vec<u8>),
    /// Not all of it yet.
    More,
    /// Not chunked encoding.
    Bad,
}

/// Decode `raw` (RFC 9112 §7.1); trailers after the last chunk are not read.
pub(super) fn dechunk(raw: &[u8]) -> Chunks {
    let mut body = Vec::new();
    let mut at = 0;
    loop {
        let Some(end) = raw[at..].windows(2).position(|w| w == b"\r\n") else {
            return Chunks::More;
        };
        let line = &raw[at..at + end];
        let size = line.split(|b| *b == b';').next().unwrap_or_default();
        let Some(size) = std::str::from_utf8(size)
            .ok()
            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
        else {
            return Chunks::Bad;
        };
        at += end + 2;
        if size == 0 {
            return Chunks::Done(body);
        }
        let Some(data_end) = at.checked_add(size) else {
            return Chunks::Bad;
        };
        if raw.len() < data_end.saturating_add(2) {
            return Chunks::More;
        }
        if &raw[data_end..data_end + 2] != b"\r\n" {
            return Chunks::Bad;
        }
        body.extend_from_slice(&raw[at..data_end]);
        at = data_end + 2;
    }
}

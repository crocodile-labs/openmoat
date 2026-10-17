use super::*;

/// Feed `stream` in pieces of `step` bytes; returns how many bytes were body.
fn body_len(framing: Framing, stream: &[u8], step: usize) -> Result<usize, Malformed> {
    let mut end = BodyEnd::new(framing);
    let mut total = 0;
    for piece in stream.chunks(step) {
        let n = end.feed(piece)?;
        total += n;
        if n < piece.len() {
            break;
        }
    }
    Ok(total)
}

#[test]
fn no_body_means_nothing_after_the_head_is_body() {
    assert_eq!(
        body_len(Framing::None, b"GET http://x/ HTTP/1.1\r\n\r\n", 7),
        Ok(0)
    );
    assert!(BodyEnd::new(Framing::None).done());
    assert!(BodyEnd::new(Framing::Length(0)).done());
}

#[test]
fn a_length_body_ends_after_exactly_its_length_however_it_arrives() {
    let stream = b"helloGET http://other.test/ HTTP/1.1\r\n\r\n";
    for step in [1, 2, 3, 5, 64] {
        assert_eq!(
            body_len(Framing::Length(5), stream, step),
            Ok(5),
            "step {step}"
        );
    }
    let mut end = BodyEnd::new(Framing::Length(5));
    assert_eq!(end.feed(b"123"), Ok(3));
    assert!(!end.done());
    assert_eq!(end.feed(b"45 and more"), Ok(2));
    assert!(end.done());
    assert_eq!(end.feed(b"anything"), Ok(0));
}

#[test]
fn a_chunked_body_ends_after_the_last_chunk_and_trailers() {
    let body =
        b"5\r\nhello\r\n1a;name=value\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nX-Trailer: t\r\n\r\n";
    let stream = [&body[..], b"GET http://other.test/ HTTP/1.1\r\n\r\n"].concat();
    for step in [1, 2, 7, 1024] {
        assert_eq!(
            body_len(Framing::Chunked, &stream, step),
            Ok(body.len()),
            "step {step}"
        );
    }
    let bare = b"3\r\nabc\r\n0\r\n\r\nNEXT";
    assert_eq!(body_len(Framing::Chunked, bare, 4), Ok(bare.len() - 4));
    let spaced = b"3 ;ext\r\nabc\r\n000\r\n\r\n";
    assert_eq!(body_len(Framing::Chunked, spaced, 1), Ok(spaced.len()));
}

#[test]
fn chunked_framing_a_server_could_read_differently_is_malformed() {
    for bad in [
        &b"\r\n"[..],                 // no size
        b"x\r\n",                     // not hex
        b"5 5\r\nhello\r\n0\r\n\r\n", // a second number after a space
        b"5\nhello",                  // bare LF ends the size line
        b"5\r\nhello..",              // data not followed by CRLF
        b"0\r\n\n",                   // bare LF in the trailers
        b"10000000000000000\r\n",     // over u64
    ] {
        assert_eq!(
            body_len(Framing::Chunked, bad, 1),
            Err(Malformed),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    let long = [vec![b'1'], vec![b';'; MAX_LINE], b"\r\n".to_vec()].concat();
    assert_eq!(body_len(Framing::Chunked, &long, 512), Err(Malformed));
}

#[test]
fn the_framing_comes_from_the_forwarded_head() {
    let head =
        |extra: &str| format!("POST /u HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n");
    assert_eq!(framing(head("").as_bytes()), Framing::None);
    assert_eq!(
        framing(head("Content-Length: 42\r\n").as_bytes()),
        Framing::Length(42)
    );
    assert_eq!(
        framing(head("transfer-encoding: chunked\r\n").as_bytes()),
        Framing::Chunked
    );
    assert_eq!(framing(b"not a head"), Framing::None);
}

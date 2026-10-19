//! A service of the proxy's own process on the proxy's port (ADR-028).
//!
//! `moat run`'s sandbox lets the agent reach one TCP port: the proxy's. The
//! hooks the agent starts run in that sandbox too, so their decisions are made
//! by the process outside it, over the same port. A connection whose first
//! bytes are a [`LocalService::prefix`] is handed to that service instead of
//! being read as an HTTP request; no HTTP request line starts with it.

use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

/// A service that shares the proxy's port.
pub trait LocalService: Sync {
    /// The bytes a connection for this service starts with. Not empty, and
    /// not the start of any HTTP method.
    fn prefix(&self) -> &[u8];

    /// Serve one connection. Its first bytes are [`Self::prefix`], still
    /// unread. The service records what it decides itself.
    fn serve(&self, client: &TcpStream);
}

/// How long to wait between looks at a connection that sent part of a prefix.
const PEEK_PAUSE: Duration = Duration::from_millis(2);

/// Whether `client` starts with `prefix`, without consuming anything. `false`
/// as soon as its bytes differ, at end of data, on an error or at `deadline`.
pub(crate) fn starts_with(client: &TcpStream, prefix: &[u8], deadline: Instant) -> bool {
    let mut seen = vec![0u8; prefix.len()];
    loop {
        let n = match client.peek(&mut seen) {
            Ok(0) | Err(_) => return false,
            Ok(n) => n,
        };
        if seen[..n] != prefix[..n] {
            return false;
        }
        if n == prefix.len() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        // `peek` returns what is there at once; wait for the rest.
        thread::sleep(PEEK_PAUSE);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{Shutdown, TcpListener};

    use super::*;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_millis(500)
    }

    #[test]
    fn a_prefix_is_matched_without_consuming_it() {
        let (mut server, mut client) = pair();
        client.write_all(b"MOAT-X/1\nrest").unwrap();
        assert!(starts_with(&server, b"MOAT-X/1\n", soon()));
        let mut all = Vec::new();
        client.shutdown(Shutdown::Write).unwrap();
        server.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"MOAT-X/1\nrest");
    }

    #[test]
    fn a_prefix_sent_in_pieces_is_matched() {
        let (server, mut client) = pair();
        let writer = thread::spawn(move || {
            client.write_all(b"MOAT").unwrap();
            thread::sleep(Duration::from_millis(30));
            client.write_all(b"-X/1\n").unwrap();
            client
        });
        assert!(starts_with(&server, b"MOAT-X/1\n", soon()));
        drop(writer.join());
    }

    #[test]
    fn http_a_short_stream_and_silence_are_not_matched() {
        let (server, mut client) = pair();
        client.write_all(b"GET http://a/ HTTP/1.1\r\n").unwrap();
        assert!(!starts_with(&server, b"MOAT-X/1\n", soon()));
        let (server, mut client) = pair();
        client.write_all(b"MOA").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        thread::sleep(Duration::from_millis(20));
        assert!(!starts_with(&server, b"MOAT-X/1\n", soon()));
        let (server, _client) = pair();
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        assert!(!starts_with(&server, b"MOAT-X/1\n", deadline));
    }
}

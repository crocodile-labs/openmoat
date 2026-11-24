//! `openmoat run --listen PORT` on Linux (ADR-108 §7): the port the agent
//! serves inside its network namespace, reachable on this machine's loopback.
//!
//! The namespace's only interface is its own loopback, so a socket the agent
//! binds there, on any address, is reachable from nowhere else. Outside, this
//! process listens on `127.0.0.1:PORT` (never another address) and hands each
//! connection to `moat isolated` inside over a Unix socket in the session's
//! directory: `moat isolated` keeps one connection to that socket waiting, and
//! when the first bytes of a client arrive on it, connects to the agent's port
//! on the namespace's loopback, sends them on and copies both ways. Inside, the
//! connections are made by `moat isolated`'s own thread, outside the agent's
//! Landlock layer; the agent itself may bind that one port and connect only to
//! the proxy, and its seccomp filter refuses it any Unix socket.

use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};

/// The socket's name in the session's directory, no longer than the proxy's
/// (`proxy.sock`), for which the directory's path was sized.
pub(super) const SOCKET: &str = "serve.sock";

/// Where the socket is for a session whose proxy socket is `proxy_socket`.
pub(super) fn socket_beside(proxy_socket: &Path) -> PathBuf {
    proxy_socket.with_file_name(SOCKET)
}

/// Outside: listen on this machine's loopback `port` and relay each client to
/// the agent's port inside through `socket`. Bound before the agent starts,
/// so a port in use stops the run with that reason.
pub(super) fn forward_in(socket: &Path, port: u16) -> Result<()> {
    let outside = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).with_context(|| {
        format!(
            "listening on 127.0.0.1:{port} for `--listen`: is another program (another \
             Gateway) using the port?"
        )
    })?;
    let inside =
        UnixListener::bind(socket).with_context(|| format!("listening on {}", socket.display()))?;
    std::thread::spawn(move || {
        for client in outside.incoming().flatten() {
            // The connection `moat isolated` keeps waiting: one per client.
            let Ok((unix, _)) = inside.accept() else {
                return;
            };
            std::thread::spawn(move || splice(&client, &unix));
        }
    });
    Ok(())
}

/// Inside (`moat isolated`): keep one connection to `socket` waiting; each
/// one that receives a client's first bytes is joined to `port` on this
/// namespace's loopback.
pub(super) fn serve_inside(socket: PathBuf, port: u16) {
    std::thread::spawn(move || {
        loop {
            let Ok(mut unix) = UnixStream::connect(&socket) else {
                // The run outside has ended, or not bound the socket yet.
                std::thread::sleep(Duration::from_millis(200));
                continue;
            };
            let mut first = [0_u8; 16 * 1024];
            let read = match unix.read(&mut first) {
                Ok(0) | Err(_) => continue,
                Ok(read) => read,
            };
            std::thread::spawn(move || {
                if let Ok(mut agent) = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    && agent.write_all(&first[..read]).is_ok()
                {
                    splice(&agent, &unix);
                }
            });
        }
    });
}

/// Copy both ways between `tcp` and `unix`; each side's end of data closes
/// the other's sending half.
fn splice(tcp: &TcpStream, unix: &UnixStream) {
    let (Ok(tcp_out), Ok(unix_in)) = (tcp.try_clone(), unix.try_clone()) else {
        return;
    };
    let back = std::thread::spawn(move || {
        let _ = io::copy(&mut &unix_in, &mut &tcp_out);
        let _ = tcp_out.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut &*tcp, &mut &*unix);
    let _ = unix.shutdown(Shutdown::Write);
    let _ = back.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client on this machine's loopback reaches a server inside through the
    /// two relays, both ways; the outside listener is on loopback alone.
    #[test]
    fn a_client_reaches_the_served_port_through_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET);
        // The agent's server, on a port of its own (here, the same namespace).
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let inner = server.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut conn, _) = server.accept().unwrap();
            let mut got = [0_u8; 5];
            conn.read_exact(&mut got).unwrap();
            conn.write_all(&got.map(|b| b.to_ascii_uppercase()))
                .unwrap();
        });
        let outer = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = outer.local_addr().unwrap().port();
        drop(outer);
        forward_in(&socket, port).unwrap();
        serve_inside(socket, inner);
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        client.write_all(b"hello").unwrap();
        let mut back = [0_u8; 5];
        client.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"HELLO");
    }

    /// The port taken already stops the run before anything starts.
    #[test]
    fn a_port_in_use_is_refused_with_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = taken.local_addr().unwrap().port();
        let error = forward_in(&dir.path().join(SOCKET), port).unwrap_err();
        assert!(
            format!("{error:#}").contains("another program"),
            "{error:#}"
        );
    }
}

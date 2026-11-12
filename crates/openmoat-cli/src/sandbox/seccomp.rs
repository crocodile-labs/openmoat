//! Lightweight tier on Linux: the sockets the agent may create, for the
//! seccomp filter `moat run` applies after the Landlock rules ([`super::landlock`]),
//! which restrict files and TCP only.
//!
//! The agent may create TCP sockets over IPv4 or IPv6, whose connections
//! Landlock limits to the proxy's port. Every other `socket()` call fails with
//! `EPERM`: Unix sockets (the user's D-Bus session bus, nscd,
//! systemd-resolved), netlink, packet, raw, UDP, SCTP and MPTCP. So name
//! resolution works only through the proxy, as on macOS: a tool that ignores
//! `HTTP(S)_PROXY` cannot resolve names. `socketpair()` stays allowed for
//! stream and sequenced-packet sockets, which are connected only to each other
//! (Node uses them for the pipes of the processes it starts). A datagram pair
//! is refused: a datagram socket can be connected again, or sent to with an
//! address, so it would reach any pathname datagram socket (`/dev/log`,
//! journald's) on a kernel without Landlock ABI 9 (ADR-082).

/// Linux's values, the same on every architecture `moat run` supports.
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_SEQPACKET: u32 = 5;
const SOCK_NONBLOCK: u32 = 0o4000;
const SOCK_CLOEXEC: u32 = 0o2_000_000;
const IPPROTO_TCP: u32 = 6;

/// The values the agent may pass to `socket(domain, type, protocol)`, argument
/// by argument. A call with any other value in any argument fails.
pub const SOCKET_ARGS: [&[u32]; 3] = [
    &[AF_INET, AF_INET6],
    &[
        SOCK_STREAM,
        SOCK_STREAM | SOCK_NONBLOCK,
        SOCK_STREAM | SOCK_CLOEXEC,
        SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
    ],
    // 0 is the default protocol of an IPv4 or IPv6 stream: TCP.
    &[0, IPPROTO_TCP],
];

/// The types the agent may pass to `socketpair(domain, type, protocol)`; a
/// call with any other type (a datagram pair) fails.
pub const SOCKETPAIR_TYPES: [u32; 8] = [
    SOCK_STREAM,
    SOCK_STREAM | SOCK_NONBLOCK,
    SOCK_STREAM | SOCK_CLOEXEC,
    SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
    SOCK_SEQPACKET,
    SOCK_SEQPACKET | SOCK_NONBLOCK,
    SOCK_SEQPACKET | SOCK_CLOEXEC,
    SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
];

#[cfg(test)]
mod tests;

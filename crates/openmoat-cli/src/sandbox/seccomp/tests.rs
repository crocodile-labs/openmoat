use super::*;

const AF_UNIX: u32 = 1;
const AF_NETLINK: u32 = 16;
const AF_PACKET: u32 = 17;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const SOCK_SEQPACKET: u32 = 5;
const IPPROTO_UDP: u32 = 17;
const IPPROTO_SCTP: u32 = 132;
const IPPROTO_MPTCP: u32 = 262;

/// How `moat run` compiles [`SOCKET_ARGS`]: a call passes when every argument
/// is one of its listed values.
fn allows(call: [u32; 3]) -> bool {
    SOCKET_ARGS
        .iter()
        .zip(call)
        .all(|(allowed, value)| allowed.contains(&value))
}

#[test]
fn tcp_over_ipv4_and_ipv6_is_allowed_with_or_without_flags() {
    for domain in [AF_INET, AF_INET6] {
        for ty in [
            SOCK_STREAM,
            SOCK_STREAM | SOCK_CLOEXEC,
            SOCK_STREAM | SOCK_NONBLOCK,
        ] {
            for protocol in [0, IPPROTO_TCP] {
                assert!(allows([domain, ty, protocol]), "{domain} {ty} {protocol}");
            }
        }
    }
}

#[test]
fn unix_netlink_packet_raw_udp_sctp_and_mptcp_are_refused() {
    let refused = [
        [AF_UNIX, SOCK_STREAM, 0],
        [AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0],
        [AF_UNIX, SOCK_DGRAM, 0],
        [AF_UNIX, SOCK_SEQPACKET, 0],
        [AF_NETLINK, SOCK_RAW, 0],
        [AF_PACKET, SOCK_RAW, 0],
        [AF_INET, SOCK_RAW, 1],
        [AF_INET, SOCK_DGRAM, 0],
        [AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP],
        [AF_INET, SOCK_STREAM, IPPROTO_SCTP],
        [AF_INET6, SOCK_STREAM, IPPROTO_MPTCP],
    ];
    for call in refused {
        assert!(!allows(call), "{call:?}");
    }
}

/// A datagram pair can be connected again or sent to with an address, so it
/// would reach a pathname datagram socket outside the sandbox (ADR-082).
#[test]
fn socket_pairs_are_streams_or_sequenced_packets_never_datagrams() {
    for ty in [SOCK_STREAM, SOCK_SEQPACKET] {
        for flags in [0, SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_NONBLOCK | SOCK_CLOEXEC] {
            assert!(SOCKETPAIR_TYPES.contains(&(ty | flags)), "{ty} {flags}");
        }
    }
    for flags in [0, SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_NONBLOCK | SOCK_CLOEXEC] {
        assert!(!SOCKETPAIR_TYPES.contains(&(SOCK_DGRAM | flags)), "{flags}");
        assert!(!SOCKETPAIR_TYPES.contains(&(SOCK_RAW | flags)), "{flags}");
    }
}

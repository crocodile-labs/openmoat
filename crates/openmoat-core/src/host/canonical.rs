//! One spelling per address, for the links of injected input (ADR-063 §4).
//!
//! [`super::of_url`] reports a host the way it was written, lowercase and
//! without a trailing dot, because net rules match that form (POLICY.md §3).
//! A client reaches the same address under other spellings: the URL Standard
//! reads `2130706433`, `0x7f.1` and `0177.0.0.1` as `127.0.0.1`, and
//! `2001:db8:0:0:0:0:0:1` is `2001:db8::1`. [`canonical`] gives each address
//! one spelling, so a host kept from untrusted output and a later call's host
//! compare equal whichever spelling each used. [`parents`] lists the domains a
//! name is under, which a later call is also checked against.

use core::net::{Ipv4Addr, Ipv6Addr};

/// `host` lowercase, without a trailing dot, an IPv4 address in any spelling
/// the URL Standard's IPv4 parser accepts as dotted decimal, and an IPv6
/// address compressed (RFC 5952). A name, or a host neither parser accepts
/// (an IPv6 zone, `1.2.3.4.5`), keeps its letters.
#[must_use]
pub(crate) fn canonical(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.contains(':') {
        return host.parse::<Ipv6Addr>().map_or(host, |ip| ip.to_string());
    }
    ipv4(&host).map_or(host, |ip| ip.to_string())
}

/// The domains `host` is under, nearest first, down to the last two labels:
/// `a.b.evil.example` → `b.evil.example`, `evil.example`. None for what is not
/// a domain name ([`super::fetchable`]: an IP address in any spelling, a
/// single label) or a name of two labels.
pub(crate) fn parents(host: &str) -> impl Iterator<Item = &str> {
    let labels = if super::fetchable(host) {
        host.split('.').count()
    } else {
        0
    };
    host.match_indices('.')
        .take(labels.saturating_sub(2))
        .map(|(at, _)| &host[at + 1..])
}

/// The URL Standard's IPv4 parser (§3.5 "IPv4 parser"): up to four parts
/// separated by `.`, each decimal, `0x` hexadecimal or `0` octal, the last
/// filling the bytes the others leave. `None` when the host does not end in a
/// number (a domain name) or a part does not fit.
fn ipv4(host: &str) -> Option<Ipv4Addr> {
    let mut parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 1 && parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    let count = u32::try_from(parts.len()).ok().filter(|n| *n <= 4)?;
    if !parts.last().is_some_and(|last| ends_in_number(last)) {
        return None;
    }
    let numbers: Vec<u64> = parts
        .iter()
        .map(|p| ipv4_number(p))
        .collect::<Option<_>>()?;
    let (last, leading) = numbers.split_last()?;
    if leading.iter().any(|n| *n > 255) || *last >= 256u64.pow(5 - count) {
        return None;
    }
    // the parts before the last are the address's first bytes, in order
    let address = leading
        .iter()
        .zip([24, 16, 8])
        .fold(*last, |sum, (n, shift)| sum + (n << shift));
    u32::try_from(address).ok().map(Ipv4Addr::from)
}

/// Whether the last part of a host is a number, which makes the URL Standard
/// read the whole host as an IPv4 address (§3.5 "ends in a number").
fn ends_in_number(last: &str) -> bool {
    !last.is_empty() && (last.bytes().all(|b| b.is_ascii_digit()) || ipv4_number(last).is_some())
}

/// One part of an IPv4 address (§3.5 "IPv4 number parser"): `0x` or `0X`
/// then hexadecimal, a leading `0` then octal, else decimal; empty after the
/// prefix is 0. `None` for an empty part, another digit, or a number past
/// `u64`, which no part of an address can be.
fn ipv4_number(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    let (digits, radix) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (hex, 16)
        } else if part.len() > 1
            && let Some(octal) = part.strip_prefix('0')
        {
            (octal, 8)
        } else {
            (part, 10)
        };
    if digits.is_empty() {
        return Some(0);
    }
    // `from_str_radix` also takes a leading `+`, which no URL parser does
    digits
        .chars()
        .all(|c| c.is_digit(radix))
        .then(|| u64::from_str_radix(digits, radix).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::{canonical, parents};

    #[test]
    fn every_spelling_of_an_address_is_one_host() {
        for (written, host) in [
            ("Evil.Example.", "evil.example"),
            ("2130706433", "127.0.0.1"),
            ("0x7f000001", "127.0.0.1"),
            ("0x7f.1", "127.0.0.1"),
            ("0177.0.0.1", "127.0.0.1"),
            ("127.1", "127.0.0.1"),
            ("127.0.0.1.", "127.0.0.1"),
            ("3405803783", "203.0.113.7"),
            ("0xCB.0.0x71.07", "203.0.113.7"),
            ("203.0.113.7", "203.0.113.7"),
            ("0x", "0.0.0.0"),
            ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
            ("0:0:0:0:0:0:0:1", "::1"),
            ("::ffff:7f00:1", "::ffff:127.0.0.1"),
        ] {
            assert_eq!(canonical(written), host, "{written}");
        }
    }

    #[test]
    fn what_no_parser_reads_as_an_address_keeps_its_letters() {
        for host in [
            "app.run",
            "1.2.3.4.5",
            "256.1.1.1",
            "1.2.3.256x",
            "4294967296",
            "0x1g",
            "1.+2",
            "99999999999999999999999",
            "fe80::1%25en0",
            "a_b.evil.com",
            "evil.0x",
        ] {
            assert_eq!(canonical(host), host, "{host}");
        }
    }

    #[test]
    fn parents_stop_at_two_labels_and_skip_addresses() {
        let all = |host| parents(host).collect::<Vec<_>>();
        assert_eq!(all("a.b.evil.example"), ["b.evil.example", "evil.example"]);
        assert_eq!(all("collect.evil.example"), ["evil.example"]);
        for host in ["evil.example", "intranet", "203.0.113.7", "2001:db8::1"] {
            assert_eq!(parents(host).next(), None, "{host}");
        }
    }
}

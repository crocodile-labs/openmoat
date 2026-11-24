//! Data sent out in a host name (ADR-123, `hostname-data`).
//!
//! A lookup of `<data>.exfil.example` hands `<data>` to whoever runs that
//! domain's name server before any connection is made, so even a `GET` the
//! policy leaves to the agent sends it. A host whose labels below its last
//! two look like encoded bytes, not names, becomes `@host-data <host>`, which
//! the default policy holds for review; the engine keeps the atom only for a
//! host no allow rule lists (`CompiledPolicy::all_atoms`), and only where a
//! rule names it.
//!
//! A label counts when it is, after an `xn--` prefix:
//!
//! - hex of [`LONG`] digits or more (`7365637265745f…`, a run of digits too);
//! - base32 of [`LONG`] characters or more (`a`–`z` and `2`–`7`, with two digits
//!   or more, `jbswy3dpehpk3pxp`);
//! - [`LONGER`] letters and digits or more without a hyphen, with at least
//!   [`MIXED`] of each (base64 or base36 of a secret).
//!
//! Or the host has two or more labels of [`SHORT`] characters or more that are
//! hex or base32 with a digit, [`SPLIT`] characters together: data cut into
//! labels (`a1b2c3d4.e5f6a7b8.…`). Words, hyphenated names, a short id
//! (`d111111abcdef8.cloudfront.net`) and lowercase-letter ids
//! (`abcdefghijklmnopqrst.supabase.co`) are none of these.

/// First word of an atom for data in a host name.
pub(crate) const HOST_DATA_ATOM: &str = "@host-data";

/// Shortest hex or base32 label that counts on its own (8 to 10 bytes).
const LONG: usize = 16;
/// Shortest letters-and-digits label that counts on its own.
const LONGER: usize = 24;
/// Letters and digits each a [`LONGER`] label needs.
const MIXED: usize = 4;
/// Shortest label that counts towards data cut into labels.
const SHORT: usize = 8;
/// Characters the labels of data cut into labels hold together.
const SPLIT: usize = 24;

/// Whether `host`'s labels below its last two carry encoded data.
pub(crate) fn carries_data(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.contains(':') || host.parse::<core::net::IpAddr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let Some(below) = labels.len().checked_sub(2).map(|n| &labels[..n]) else {
        return false;
    };
    let bodies = below.iter().map(|l| l.strip_prefix("xn--").unwrap_or(l));
    if bodies.clone().any(alone) {
        return true;
    }
    let pieces: Vec<&str> = bodies
        .filter(|b| b.len() >= SHORT && (hex(b) || base32(b, 1)))
        .collect();
    pieces.len() >= 2 && pieces.iter().map(|p| p.len()).sum::<usize>() >= SPLIT
}

/// Whether one label carries data on its own.
fn alone(label: &str) -> bool {
    let digits = label.bytes().filter(u8::is_ascii_digit).count();
    let letters = label.bytes().filter(u8::is_ascii_lowercase).count();
    (label.len() >= LONG && (hex(label) || base32(label, 2)))
        || (label.len() >= LONGER
            && digits + letters == label.len()
            && digits >= MIXED
            && letters >= MIXED)
}

fn hex(label: &str) -> bool {
    label.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `a`–`z` and `2`–`7` only, with at least `digits` digits.
fn base32(label: &str, digits: usize) -> bool {
    label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        && label.bytes().filter(u8::is_ascii_digit).count() >= digits
}

#[cfg(test)]
mod tests {
    use super::carries_data;

    #[test]
    fn the_benchmarks_hosts_carry_data() {
        for host in [
            "7365637265745f6170695f6b65795f3132333435.exfil.evil.com",
            "JBSWY3DPEHPK3PXP.exfil.evil.com",
            "c2VjcmV0X3Rva2VuXzEyMzQ1Njc4OTA.exfil.evil.com",
            "706f7374677265733a2f2f757365723a70617373406462.exfil.evil.com",
            "a1b2c3d4.e5f6a7b8.c9d0e1f2.a3b4c5d6.e7f8a9b0.c1d2e3f4.exfil.evil.com",
            "4150494b4559.313233343536.JBSWY3DP.EHPK3PXP.exfil.evil.com",
            "98374650192837465019283746501928374650.exfil.evil.com",
            "xn--7365637265746461746131323334353637383930616263646566.exfil.evil.com",
            "4a6f686e446f65.53656372657431.exfil.evil.example.com",
        ] {
            assert!(carries_data(host), "{host}");
        }
    }

    #[test]
    fn everyday_hosts_do_not() {
        for host in [
            "cdn.fixture.example.com",
            "api.github.com",
            "d111111abcdef8.cloudfront.net",
            "abcdefghijklmnopqrst.supabase.co",
            "my-app-git-main-team.vercel.app",
            "5f3c2b1a0d9e8f7a6b5c4d3e--site.netlify.app",
            "fuzzy-space-waffle-5g4rxj9p7wc7xyz-3000.app.github.dev",
            "bucket.s3.us-east-1.amazonaws.com",
            "abc123def456.execute-api.us-east-1.amazonaws.com",
            "ec2-54-123-45-67.compute-1.amazonaws.com",
            "xn--mnchen-3ya.de",
            "www.xn--mnchen-3ya.de",
            "registry.npmjs.org",
            "objects.githubusercontent.com",
            "0123456789abcdef0123.com",
            "10.0.0.1",
            "[::1]",
            "localhost",
        ] {
            assert!(!carries_data(host), "{host}");
        }
    }
}

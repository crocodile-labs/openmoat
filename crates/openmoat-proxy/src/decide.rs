//! Which hosts and addresses the proxy may reach.
//!
//! A host is decided exactly as `moat guard` decides a fetch tool's URL: one
//! `fetch` atom through openmoat-core's [`CompiledPolicy`], so `fetch` and `net`
//! lists both apply and deny rules come first. The proxy cannot prompt, so an
//! `ask` is refused. Cloud metadata and link-local addresses are refused
//! whatever the policy says, by name and again after DNS resolution. Private
//! and CGNAT addresses are refused unless an allow rule names the address.
//! Every resolved address is also checked against the deny rules, so a deny
//! naming an address holds for a name that resolves to it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use openmoat_core::{
    Action, AtomicAction, CompiledPolicy, Decision, Defaults, Kind, MapPathResolver, Policy, Taint,
    Verdict,
};

/// Rule id for a destination refused whatever the policy says.
pub const RULE_ADDRESS: &str = "proxy-address";
/// Rule id for a tunnel whose TLS SNI is missing or names another host.
pub const RULE_SNI: &str = "proxy-sni";
/// Rule id for a request the proxy could not parse or does not serve.
pub const RULE_REQUEST: &str = "proxy-request";
/// Rule id for a destination that could not be resolved or reached.
pub const RULE_UPSTREAM: &str = "proxy-upstream";
/// Rule id for a connection refused because it could not be recorded.
pub const RULE_AUDIT: &str = "proxy-audit";

/// Metadata services reachable by name on cloud instances.
const METADATA_NAMES: &[&str] = &["metadata.google.internal", "metadata.goog"];
const ALIBABA_METADATA: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);
/// Azure's `WireServer`, which serves instance configuration and keys to the VM.
const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);
const AWS_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);
/// RFC 6052 well-known NAT64 prefix: `64:ff9b::a.b.c.d` reaches `a.b.c.d`.
const NAT64: [u16; 6] = [0x64, 0xff9b, 0, 0, 0, 0];
/// RFC 8215 local-use NAT64 prefix `64:ff9b:1::/48`. The operator picks how the
/// IPv4 address is embedded inside it, so its addresses count as local network.
const NAT64_LOCAL: [u16; 3] = [0x64, 0xff9b, 1];
/// Ranges on the local network (or the carrier's), each with its description.
const PRIVATE_V4: [(Ipv4Addr, u8, &str); 6] = [
    (
        Ipv4Addr::new(10, 0, 0, 0),
        8,
        "a private address (10.0.0.0/8)",
    ),
    (
        Ipv4Addr::new(172, 16, 0, 0),
        12,
        "a private address (172.16.0.0/12)",
    ),
    (
        Ipv4Addr::new(192, 168, 0, 0),
        16,
        "a private address (192.168.0.0/16)",
    ),
    (
        Ipv4Addr::new(100, 64, 0, 0),
        10,
        "a shared CGNAT address (100.64.0.0/10)",
    ),
    (
        Ipv4Addr::new(198, 18, 0, 0),
        15,
        "a benchmarking address (198.18.0.0/15)",
    ),
    (
        Ipv4Addr::new(192, 0, 0, 0),
        24,
        "an IETF protocol address (192.0.0.0/24)",
    ),
];

/// Decide whether `host`, normalised as [`Request::host`](crate::Request::host)
/// reports it, may be reached. Only an `allow` lets the connection proceed.
#[must_use]
pub fn host(policy: &CompiledPolicy<'_>, host: &str) -> Decision {
    if METADATA_NAMES
        .iter()
        .any(|m| host == *m || host.strip_suffix(m).is_some_and(|p| p.ends_with('.')))
    {
        return Decision::single(
            Verdict::Deny,
            RULE_ADDRESS,
            format!("{host} is a cloud metadata service"),
        );
    }
    let atom = AtomicAction::Fetch {
        host: host.to_owned(),
    };
    let mut decision = policy.evaluate_atomic(&atom).unwrap_or_else(|| {
        Decision::single(
            Verdict::Deny,
            RULE_REQUEST,
            format!("no rule decided {host}"),
        )
    });
    // A deferred host (ADR-025) is refused too: the agent's permission flow never sees
    // the proxy's connections.
    if matches!(decision.verdict, Verdict::Ask | Verdict::Defer) {
        decision.verdict = Verdict::Deny;
        decision
            .reasons
            .push("the proxy cannot ask, so a host the hook would ask for or leave to the agent is refused".to_owned());
    }
    decision
}

/// The refusal for a request to `host:port` from a session with `taint`, if
/// any (ADR-027). The core's taint rules decide (POLICY.md §4.1): after the
/// session read secret material, network to every host but that secret's own
/// asks. The proxy cannot ask, so that ask is refused. Untrusted content alone
/// changes nothing here: its taint protects writes.
#[must_use]
pub fn tainted(
    policy: &CompiledPolicy<'_>,
    host: &str,
    port: u16,
    taint: &Taint,
) -> Option<Decision> {
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let action = Action::Net {
        url: format!("https://{authority}/"),
    };
    let mut decision = policy.with_taint(
        Decision::new(Verdict::Allow),
        &action,
        &MapPathResolver::default(),
        taint,
    );
    if decision.verdict == Verdict::Allow {
        return None;
    }
    decision.verdict = Verdict::Deny;
    decision.reasons.push(
        "the proxy cannot ask, so a session that read secret material reaches only that \
         secret's own host until it ends; `moat allow` does not answer a secret's taint, \
         so start a new session"
            .to_owned(),
    );
    Some(decision)
}

/// Why the proxy never connects to `ip`, if it does not. Checked on every
/// resolved address, so a name the policy allows cannot be pointed at a local
/// or metadata service (DNS rebinding).
#[must_use]
pub fn forbidden(ip: IpAddr) -> Option<Forbidden> {
    match ip.to_canonical() {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

/// The classes of address the proxy refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Forbidden {
    /// This machine (`127.0.0.0/8`, `::1`), including the proxy itself.
    Loopback,
    /// Link-local (`169.254.0.0/16`, `fe80::/10`): where cloud metadata lives.
    LinkLocal,
    /// A cloud metadata address outside the link-local ranges.
    Metadata,
    /// Unspecified, broadcast, multicast or `0.0.0.0/8`: never a server.
    NotUnicast,
    /// Private, CGNAT, benchmarking or unique-local (`fc00::/7`): reachable
    /// only when an allow rule names the address ([`named`]). Carries the
    /// description naming the range.
    Private(&'static str),
}

impl Forbidden {
    /// A short phrase for reasons and the audit log.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Loopback => "a loopback address",
            Self::LinkLocal => "a link-local address",
            Self::Metadata => "a cloud metadata address",
            Self::NotUnicast => "not a unicast address",
            Self::Private(range) => range,
        }
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> Option<Forbidden> {
    if ip.is_loopback() {
        Some(Forbidden::Loopback)
    } else if ip.is_link_local() {
        Some(Forbidden::LinkLocal)
    } else if ip == ALIBABA_METADATA || ip == AZURE_WIRESERVER {
        Some(Forbidden::Metadata)
    } else if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.octets()[0] == 0 {
        Some(Forbidden::NotUnicast)
    } else {
        PRIVATE_V4
            .iter()
            .find(|(net, len, _)| u32::from(ip) >> (32 - len) == u32::from(*net) >> (32 - len))
            .map(|(_, _, range)| Forbidden::Private(range))
    }
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<Forbidden> {
    let seg = ip.segments();
    if ip.is_loopback() {
        Some(Forbidden::Loopback)
    } else if ip.is_unspecified() || ip.is_multicast() {
        Some(Forbidden::NotUnicast)
    } else if seg[0] & 0xffc0 == 0xfe80 {
        Some(Forbidden::LinkLocal)
    } else if ip == AWS_METADATA_V6 {
        Some(Forbidden::Metadata)
    } else if let Some(v4) = carried_v4(ip) {
        forbidden_v4(v4)
    } else if let Some(why) = tunnelled_v4(ip).find_map(forbidden_v4) {
        Some(why)
    } else if seg[..3] == NAT64_LOCAL {
        // The common /96 layout first, so a metadata or loopback address in it
        // is named as such; any other layout is local network all the same.
        let [a, b] = seg[6].to_be_bytes();
        let [c, d] = seg[7].to_be_bytes();
        forbidden_v4(Ipv4Addr::new(a, b, c, d)).or(Some(Forbidden::Private(
            "a local-use NAT64 address (64:ff9b:1::/48)",
        )))
    } else if seg[0] & 0xfe00 == 0xfc00 {
        Some(Forbidden::Private("a unique local address (fc00::/7)"))
    } else {
        None
    }
}

/// The IPv4 address a well-known NAT64 (`64:ff9b::/96`) or deprecated
/// IPv4-compatible (`::/96`) address reaches.
fn carried_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = ip.segments();
    (seg[..6] == NAT64 || seg[..6] == [0; 6]).then(|| {
        let [a, b] = seg[6].to_be_bytes();
        let [c, d] = seg[7].to_be_bytes();
        Ipv4Addr::new(a, b, c, d)
    })
}

/// The IPv4 addresses a 6to4 (`2002::/16`: the address in bits 16..48) or
/// Teredo (`2001::/32`: the server in bits 32..64, the client inverted in the
/// last 32 bits) address leads to: a relay or the server delivers it there.
fn tunnelled_v4(ip: Ipv6Addr) -> impl Iterator<Item = Ipv4Addr> {
    let o = ip.octets();
    let six_to_four = (o[..2] == [0x20, 0x02]).then(|| Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    let teredo = o[..4] == [0x20, 0x01, 0, 0];
    let client = teredo.then(|| Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]));
    let server = teredo.then(|| Ipv4Addr::new(o[4], o[5], o[6], o[7]));
    [six_to_four, client, server].into_iter().flatten()
}

/// The part of `policy` that decides a resolved address: its deny rules, and
/// the allow rules' `net` and `fetch` patterns that name an address: a pattern
/// starting with a digit or containing `:`, not starting with a glob
/// metacharacter, and made only of what an address's text and a glob use.
/// Anything else is left undecided (`ask`), which neither opens a
/// [`Forbidden::Private`] address ([`named`]) nor refuses one ([`denied`]), so
/// a wildcard such as `*` or `*.example`, or a name such as
/// `db.internal:5432`, never reaches the local network by DNS.
#[must_use]
pub fn address_policy(policy: &Policy) -> Policy {
    let allow = policy
        .allow
        .iter()
        .map(|g| {
            let keep = |list: &[String]| {
                list.iter()
                    .filter(|p| names_address(p))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            openmoat_core::RuleGroup {
                id: g.id.clone(),
                reason: g.reason.clone(),
                net: keep(g.patterns(Kind::Net)),
                fetch: keep(g.patterns(Kind::Fetch)),
                ..Default::default()
            }
        })
        .collect();
    // Not `deny`: only a deny rule may refuse an address the host check passed.
    Policy {
        defaults: Defaults::All(Verdict::Ask),
        deny: policy.deny.clone(),
        allow,
        ask: Vec::new(),
        ..policy.clone()
    }
}

/// Whether a host pattern names an address (see [`address_policy`]).
fn names_address(pattern: &str) -> bool {
    !pattern.starts_with(['*', '?', '[', '{'])
        && (pattern.starts_with(|c: char| c.is_ascii_digit()) || pattern.contains(':'))
        && pattern
            .chars()
            .all(|c| c.is_ascii_hexdigit() || ".:*?[]{},!-".contains(c))
}

/// Whether `addresses` (compiled from [`address_policy`]) allows `ip`, matched
/// in its canonical text form (`::ffff:10.0.0.5` as `10.0.0.5`).
#[must_use]
pub fn named(addresses: &CompiledPolicy<'_>, ip: IpAddr) -> bool {
    let atom = AtomicAction::Fetch {
        host: ip.to_canonical().to_string(),
    };
    addresses
        .evaluate_atomic(&atom)
        .is_some_and(|d| d.verdict == Verdict::Allow)
}

/// The deny rules of `addresses` (compiled from [`address_policy`]) that
/// match `ip`, if any: a deny naming an address holds for every name that
/// resolves to it. Matched in canonical text form, and for a NAT64,
/// IPv4-compatible, 6to4 or Teredo address also as the IPv4 addresses it
/// reaches. Allow rules never widen anything here; an address no deny rule
/// matches gives `None`.
#[must_use]
pub fn denied(addresses: &CompiledPolicy<'_>, ip: IpAddr) -> Option<Decision> {
    let ip = ip.to_canonical();
    let carried: Vec<IpAddr> = match ip {
        IpAddr::V6(v6) => carried_v4(v6)
            .into_iter()
            .chain(tunnelled_v4(v6))
            .map(IpAddr::V4)
            .collect(),
        IpAddr::V4(_) => Vec::new(),
    };
    std::iter::once(ip).chain(carried).find_map(|ip| {
        let atom = AtomicAction::Fetch {
            host: ip.to_string(),
        };
        addresses
            .evaluate_atomic(&atom)
            .filter(|d| d.verdict == Verdict::Deny)
    })
}

#[cfg(test)]
mod tests;

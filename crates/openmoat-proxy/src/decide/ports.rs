//! Which ports of a host the proxy may reach.
//!
//! A `net` or `fetch` pattern without a port allows the hosts it matches on
//! [`DEFAULT_PORTS`] only. A pattern `host:port` ([`port_pattern`]) allows the
//! hosts its host part matches on that one port, whether or not a pattern
//! without a port names them, as `example.com` allows `example.com` on 443.
//! Deny rules hold on every port, and a host an allow list excludes without a
//! port is excluded on every port. IPv6 literals take no port: they are
//! reached on the default ports only.

use openmoat_core::{
    AtomicAction, CompiledPolicy, Decision, Defaults, Kind, Policy, RuleGroup, Verdict,
    port_pattern,
};

/// Rule id for a host the policy allows, refused on a port no rule names.
pub const RULE_PORT: &str = "proxy-port";

/// The ports a host pattern without a port allows: HTTPS and HTTP.
pub const DEFAULT_PORTS: [u16; 2] = [443, 80];

/// The part of `policy` that decides a host and its port, as
/// [`host_port`] uses it: every deny and repository ask rule as written, and
/// the allow rules' `host:port` patterns only, so that a pattern without a
/// port (`*`, `example.com`) never opens another port. Every exclusion
/// without a port (`!evil.example.com`) also excludes the host on every port.
/// Anything else is left to the caller (`defer`).
#[must_use]
pub fn port_policy(policy: &Policy) -> Policy {
    let lists = |groups: &[RuleGroup], ported_only: bool| -> Vec<RuleGroup> {
        groups
            .iter()
            .map(|g| RuleGroup {
                id: g.id.clone(),
                reason: g.reason.clone(),
                net: with_ports(g.patterns(Kind::Net), ported_only),
                fetch: with_ports(g.patterns(Kind::Fetch), ported_only),
                ..Default::default()
            })
            .collect()
    };
    Policy {
        defaults: Defaults::All(Verdict::Defer),
        deny: lists(&policy.deny, false),
        repo_ask: lists(&policy.repo_ask, false),
        allow: lists(&policy.allow, true),
        ask: Vec::new(),
        defer: Vec::new(),
        ..policy.clone()
    }
}

/// `list` (only its `host:port` patterns when `ported_only`), and `!host:*`
/// for each exclusion `!host` without a port. An IPv6 exclusion gets none: it
/// takes no port, and its `:` would make `!host:*` match other addresses.
pub(super) fn with_ports(list: &[String], ported_only: bool) -> Vec<String> {
    let kept = list
        .iter()
        .filter(|p| !ported_only || port_pattern(p.strip_prefix('!').unwrap_or(p)).is_some());
    let excluded = list
        .iter()
        .filter_map(|p| p.strip_prefix('!'))
        .filter(|host| !host.contains(':'))
        .map(|host| format!("!{host}:*"));
    kept.cloned().chain(excluded).collect()
}

/// `host:port` as patterns name it; `None` for an IPv6 address.
fn ported(host: &str, port: u16) -> Option<String> {
    (!host.contains(':')).then(|| format!("{host}:{port}"))
}

/// Decide whether `host`, normalised as [`Request::host`](crate::Request::host)
/// reports it, may be reached on `port`. `ports` is compiled from
/// [`port_policy`] of `policy`'s policy. Only an `allow` lets the connection
/// proceed:
///
/// - a deny or repository ask rule naming the host, or `host:port`, refuses;
/// - an allow rule naming `host:port` allows;
/// - otherwise the host is decided as [`host`](super::host) decides it, and an
///   allowed host passes on [`DEFAULT_PORTS`] only: any other port is refused
///   with [`RULE_PORT`].
#[must_use]
pub fn host_port(
    policy: &CompiledPolicy<'_>,
    ports: &CompiledPolicy<'_>,
    host: &str,
    port: u16,
) -> Decision {
    let decide = |subject: String| ports.evaluate_atomic(&AtomicAction::Fetch { host: subject });
    let refused = |d: &Decision| matches!(d.verdict, Verdict::Deny | Verdict::Ask);
    if super::metadata(host).is_some() || decide(host.to_owned()).is_some_and(|d| refused(&d)) {
        return super::host(policy, host);
    }
    match ported(host, port).and_then(decide) {
        Some(d) if d.verdict == Verdict::Allow => return d,
        Some(mut d) if refused(&d) => {
            if d.verdict == Verdict::Ask {
                d.verdict = Verdict::Deny;
                d.reasons.push(
                    "the proxy cannot ask, so a host and port it would ask for is refused"
                        .to_owned(),
                );
            }
            return d;
        }
        _ => {}
    }
    let decision = super::host(policy, host);
    if decision.verdict != Verdict::Allow || DEFAULT_PORTS.contains(&port) {
        return decision;
    }
    let how = if host.contains(':') {
        "an IPv6 address is reached on those ports only".to_owned()
    } else {
        format!("a `net` rule `{host}:{port}` allows this port")
    };
    Decision::single(
        Verdict::Deny,
        RULE_PORT,
        format!("{host} is allowed on ports 443 and 80 only, not {port}; {how}"),
    )
}

#[cfg(test)]
mod tests;

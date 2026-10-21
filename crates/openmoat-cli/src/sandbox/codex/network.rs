//! `[permissions.moat.network]` of the Codex profile.

use openmoat_core::Kind;
use openmoat_core::ir::{Access, Effect};
use toml_edit::{Item, Table, value};

use crate::sandbox::patterns::{domain, split};
use crate::sandbox::{DEFAULT_NET_RULE, Report};

/// `[permissions.moat.network]`: Codex's proxy allows the listed domains.
pub(super) fn network(net: &Access, report: &mut Report) -> Table {
    let mut domains = Table::new();
    if net.default == Effect::Allow {
        report.loss(
            Kind::Net,
            DEFAULT_NET_RULE,
            "the profile cannot allow every host: commands reach only listed hosts".into(),
        );
    }
    for rule in &net.allow {
        let (positive, excluded) = split(&rule.patterns);
        if !excluded.iter().all(|p| domain(p)) {
            report.loss(
                Kind::Net,
                &rule.id,
                "an exception is not a domain name, so the whole rule is left out: denied".into(),
            );
            continue;
        }
        for pattern in positive {
            if domain(pattern) {
                domains.insert(pattern, value("allow"));
            } else {
                report.loss(
                    Kind::Net,
                    &rule.id,
                    format!("`{pattern}` is not a domain name, so it stays denied"),
                );
            }
        }
        for pattern in excluded {
            domains.insert(pattern, value("deny"));
        }
    }
    // Hosts that are not domain names (`169.254.*`) stay unlisted, so denied.
    for rule in &net.deny {
        let (positive, _) = split(&rule.patterns);
        for pattern in positive.into_iter().filter(|p| domain(p)) {
            domains.insert(pattern, value("deny"));
        }
    }
    let mut table = Table::new();
    table.insert("enabled", value(true));
    // Codex's default, stated so that turning it on is drift: no direct
    // connection to local services.
    table.insert("allow_local_binding", value(false));
    table.insert("domains", Item::Table(domains));
    table
}

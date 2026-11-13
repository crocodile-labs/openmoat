//! The human form of a run's boundary record (ADR-089): `openmoat run
//! --print-boundary` prints it on standard output, `openmoat run --verbose`
//! on standard error before the agent starts.

use std::io::{self, Write};

use openmoat_core::boundary::{EffectiveBoundary, NetworkMode, Restriction, ToolToken, Weaker};

/// The record as lines, each without a newline.
pub fn lines(record: &EffectiveBoundary) -> Vec<String> {
    let mut lines = vec![format!(
        "boundary: {:?} tier on {} (asked: {:?})",
        record.tier, record.os, record.requested
    )];
    for downgrade in &record.downgrades {
        let what = match downgrade.what {
            Weaker::Tier => "tier",
            Weaker::Network => "network",
            Weaker::ProjectTop => "project top",
        };
        let how = if downgrade.chosen { "chosen" } else { "forced" };
        lines.push(format!("  downgrade ({what}, {how}): {}", downgrade.why));
    }
    let network = match record.network.mode {
        NetworkMode::Namespace => "a network namespace; the proxy is the only way out",
        NetworkMode::PortOnly => "port only: any host on the proxy's port",
        NetworkMode::Profile => "the Seatbelt profile allows the proxy's address alone",
    };
    lines.push(format!("  network: {network}"));
    if let Some(landlock) = &record.landlock {
        let abi = landlock
            .abi
            .map_or("none".to_owned(), |abi| abi.to_string());
        let enforced = landlock
            .enforcement
            .map_or("not yet applied".to_owned(), |e| {
                format!("{e:?}").to_lowercase()
            });
        lines.push(format!("  landlock: ABI {abi}, {enforced}"));
    }
    let token = match &record.tool_token {
        ToolToken::Withheld => "withheld by the tool-shell wrapper".to_owned(),
        ToolToken::WithheldByIntegration => "withheld by the host's integration".to_owned(),
        ToolToken::NotWithheld(why) => format!("kept by tool commands: {why}"),
        ToolToken::UnknownAgent => "no agent OpenMoat knows".to_owned(),
    };
    lines.push(format!("  relay token: {token}"));
    lines.push("  restriction             available configured applied tested".to_owned());
    lines.extend(record.restrictions.iter().map(row));
    lines
}

fn row(restriction: &Restriction) -> String {
    let yes = |b: bool| if b { "yes" } else { "no" };
    let maybe = |b: Option<bool>| b.map_or("-", yes);
    format!(
        "  {:<23} {:<9} {:<10} {:<7} {}",
        restriction.name.id(),
        yes(restriction.available),
        yes(restriction.configured),
        maybe(restriction.applied),
        maybe(restriction.tested)
    )
}

/// Write [`lines`] to `out`.
pub fn write(out: &mut impl Write, record: &EffectiveBoundary) -> io::Result<()> {
    for line in lines(record) {
        super::line(out, &line)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use openmoat_core::boundary::{
        Downgrade, Mechanism, Network, Requested, Restriction, Tier, VERSION,
    };

    use super::*;

    #[test]
    fn a_downgrade_and_every_restriction_are_shown() {
        let mut seccomp = Restriction::planned(Mechanism::Seccomp, true, true);
        seccomp.applied = Some(true);
        seccomp.tested = Some(true);
        let record = EffectiveBoundary {
            version: VERSION,
            os: "linux".to_owned(),
            requested: Requested::Default,
            tier: Tier::Lightweight,
            downgrades: vec![Downgrade {
                what: Weaker::Tier,
                chosen: false,
                why: "bubblewrap is not installed".to_owned(),
            }],
            network: Network {
                mode: NetworkMode::PortOnly,
                proxy_port: None,
            },
            landlock: None,
            tool_token: ToolToken::NotWithheld("no wrapper for this host".to_owned()),
            restrictions: vec![
                seccomp,
                Restriction::planned(Mechanism::NetworkNamespace, false, false),
            ],
            launch: None,
        };
        let shown = lines(&record).join("\n");
        for expected in [
            "boundary: Lightweight tier on linux (asked: Default)",
            "downgrade (tier, forced): bubblewrap is not installed",
            "network: port only",
            "kept by tool commands: no wrapper for this host",
            "seccomp                 yes       yes        yes     yes",
            "network_namespace       no        no         -       -",
        ] {
            assert!(shown.contains(expected), "{expected}:\n{shown}");
        }
    }
}

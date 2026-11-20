//! The human form of a run's boundary record (ADR-089): `openmoat run
//! --print-boundary` prints it on standard output, `openmoat run --verbose`
//! on standard error before the agent starts.

use std::io::{self, Write};

use openmoat_core::boundary::{
    EffectiveBoundary, NetworkMode, Restriction, RunEnvironment, ToolToken, Weaker,
};

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
    if let Some(environment) = &record.environment {
        lines.extend(environment_lines(environment));
    }
    lines.push("  restriction             available configured applied tested".to_owned());
    lines.extend(record.restrictions.iter().map(row));
    lines
}

/// What of the inherited environment passes (ADR-105), names only.
fn environment_lines(environment: &RunEnvironment) -> Vec<String> {
    let names = |list: &[String]| {
        if list.is_empty() {
            "none".to_owned()
        } else {
            list.iter()
                .map(|n| super::clean(n).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let how = if environment.scrubbed {
        "scrubbed: only the allowlist passes"
    } else {
        "inherited: every variable passes"
    };
    let mut lines = vec![format!(
        "  environment: {how} ({})",
        super::clean(&environment.why)
    )];
    if environment.scrubbed {
        lines.push(format!("    passed: {}", names(&environment.passed)));
        lines.push(format!("    withheld: {}", names(&environment.withheld)));
    }
    if !environment.brokered.is_empty() {
        lines.push(format!(
            "    placeholder instead of the value: {}",
            names(&environment.brokered)
        ));
    }
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
            environment: None,
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
        assert!(!shown.contains("environment"), "{shown}");
    }

    #[test]
    fn the_environment_names_what_passes_and_what_is_withheld() {
        let environment = RunEnvironment {
            scrubbed: true,
            why: "`openmoat run --scrub-env`".to_owned(),
            passed: vec!["HOME".to_owned(), "PATH".to_owned()],
            withheld: vec!["AWS_SECRET_ACCESS_KEY\u{1b}[31m".to_owned()],
            brokered: vec!["GITHUB_TOKEN".to_owned()],
        };
        let shown = environment_lines(&environment).join("\n");
        for expected in [
            "environment: scrubbed: only the allowlist passes (`openmoat run --scrub-env`)",
            "passed: HOME, PATH",
            "withheld: AWS_SECRET_ACCESS_KEY",
            "placeholder instead of the value: GITHUB_TOKEN",
        ] {
            assert!(shown.contains(expected), "{expected}:\n{shown}");
        }
        assert!(!shown.contains('\u{1b}'), "{shown}");
        let inherited = RunEnvironment {
            scrubbed: false,
            why: "the default (`sandbox.env: inherited`)".to_owned(),
            passed: Vec::new(),
            withheld: Vec::new(),
            brokered: Vec::new(),
        };
        let shown = environment_lines(&inherited).join("\n");
        assert!(
            shown.contains("inherited: every variable passes"),
            "{shown}"
        );
        assert!(!shown.contains("withheld"), "{shown}");
    }
}

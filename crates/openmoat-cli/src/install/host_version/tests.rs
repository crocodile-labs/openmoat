use openmoat_hosts::{Advisory, Host, Platform};

use super::{advisory_line, parse, parse_any};

/// OpenCode 1 takes the plugin; OpenCode 2 does not, and says why.
#[test]
fn only_versions_from_the_spec_major_are_unsupported() {
    let gate = Host::ALL
        .iter()
        .find_map(|h| h.spec().install.as_ref()?.unsupported.as_ref())
        .unwrap();
    assert_eq!(gate.from_major, 2);
    assert!(!gate.why.is_empty());
    assert!(parse("1.19.4").is_some_and(|v| v.0 < gate.from_major));
    assert!(parse("2.1.4").is_some_and(|v| v.0 >= gate.from_major));
}

#[test]
fn a_version_after_a_program_name_is_read() {
    assert_eq!(parse_any("1.19.4\n"), Some((1, 19, 4)));
    assert_eq!(parse_any("codex-cli 0.164.0"), Some((0, 164, 0)));
    assert_eq!(parse_any("Hermes Agent v0.22.5 (x)"), Some((0, 22, 5)));
    assert_eq!(parse_any("no version here"), None);
}

/// The OpenCode MCP OAuth advisory: Windows and WSL from 1.0.137 up to, not
/// including, 1.18.33.
#[test]
fn the_opencode_sign_in_advisory_names_its_range_and_systems() {
    let spec = &Host::OpenCode.spec().advisories;
    let pillar = |version, platform| {
        spec.affecting(version, platform)
            .any(|a| a.fixed == (1, 18, 33))
    };
    assert!(pillar((1, 18, 32), Platform::Windows));
    assert!(pillar((1, 0, 137), Platform::Wsl));
    assert!(!pillar((1, 0, 136), Platform::Windows));
    assert!(!pillar((1, 18, 33), Platform::Windows));
    assert!(!pillar((1, 18, 32), Platform::MacOs));
    assert!(!pillar((1, 18, 32), Platform::Linux));
}

/// pi's `auth.json` write race (CVE-2026-54327): 0.28.0 up to 0.78.1.
#[test]
fn the_pi_credentials_race_advisory_names_its_range() {
    let spec = &Host::Pi.spec().advisories;
    let race = |version| {
        spec.affecting(version, Platform::MacOs)
            .any(|a| a.id == "GHSA-r95r-rj6r-c39x")
    };
    assert!(!race((0, 27, 9)));
    assert!(race((0, 28, 0)));
    assert!(race((0, 78, 0)));
    assert!(!race((0, 78, 1)));
}

#[test]
fn one_line_names_the_first_advisory_and_the_version_that_fixes_all() {
    let spec = &Host::Pi.spec().advisories;
    let affecting: Vec<&Advisory> = spec.affecting((0, 60, 0), Platform::Linux).collect();
    assert_eq!(affecting.len(), 4);
    let line = advisory_line("pi", (0, 60, 0), &affecting).unwrap();
    assert!(
        line.starts_with("pi 0.60.0 has a known security advisory, "),
        "{line}"
    );
    assert!(
        line.contains(" and 3 more; upgrade to 0.79.0 or later: https://"),
        "{line}"
    );
    assert!(!line.contains('\n'), "{line}");
    // The race in `auth.json` writes is fixed in 0.78.1, the rest by 0.79.0.
    let later: Vec<&Advisory> = spec.affecting((0, 78, 1), Platform::MacOs).collect();
    let line = advisory_line("pi", (0, 78, 1), &later).unwrap();
    assert!(line.contains("; upgrade to 0.79.0 or later"), "{line}");
    assert!(!line.contains("more"), "{line}");
    assert_eq!(advisory_line("pi", (0, 79, 0), &[]), None);
}

/// Every advisory names a source, a non-empty range and a fixed version.
#[test]
fn every_advisory_has_a_source_and_a_fix() {
    let mut count = 0;
    for host in Host::EVERY {
        let advisories = &host.spec().advisories;
        for a in advisories.list {
            count += 1;
            assert!(!advisories.program.is_empty(), "{}", host.id());
            assert!(a.from < a.fixed, "{}", a.id);
            assert!(a.source.starts_with("https://"), "{}", a.id);
            assert!(!a.summary.is_empty() && !a.id.is_empty(), "{}", a.id);
        }
    }
    assert!(count > 30, "{count}");
}

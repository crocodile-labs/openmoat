use std::path::Path;

use openmoat_hosts::Host;

use super::{RepinChecks, repin_checks, unattended};
use crate::home::{Home, write_private};
use crate::install::{HostConfig, Recorded};

#[test]
fn changes_over_an_existing_lock_wait_for_a_person() {
    assert!(unattended::applies(true, false), "a detached script");
    assert!(!unattended::applies(true, true), "a person at a terminal");
    assert!(!unattended::applies(false, false), "a first install");
    assert!(!unattended::applies(false, true));
}

/// A detached `openmoat init --yes` started from a copy of the binary an
/// agent left somewhere would point every hook at that copy.
#[test]
fn an_unattended_init_keeps_the_binary_the_lock_records() {
    let recorded = Path::new("/opt/tools/bin/openmoat");
    assert!(unattended::refuse_other_binary(recorded, recorded).is_ok());
    let alias = Path::new("/opt/tools/bin/moat");
    assert!(
        unattended::refuse_other_binary(alias, recorded).is_ok(),
        "the rename: a lock from before it records `moat`"
    );
    let copy = Path::new("/home/me/.cache/x/openmoat");
    let refused = unattended::refuse_other_binary(recorded, copy).unwrap_err();
    assert!(
        refused.to_string().contains("without a person"),
        "{refused}"
    );
}

/// Where an agent keeps its files decides which MCP files the guard reads; an
/// unattended `init` with `CLAUDE_CONFIG_DIR` pointing elsewhere must not move it.
#[test]
fn an_unattended_init_keeps_each_recorded_directory() {
    let dir = tempfile::tempdir().unwrap();
    let home = |name: &str, claude: &str| {
        let home = Home::at(dir.path().join(name));
        let hosts = format!(r#"{{"version":1,"dirs":{{"claude-code":"{claude}"}}}}"#);
        write_private(&home.hosts_path(), hosts.as_bytes()).unwrap();
        home
    };
    let real = home("real", "/home/me/.claude");
    let planted =
        HostConfig::for_host(&home("planted", "/code/app/fake"), Host::ClaudeCode).unwrap();
    for (unattended, kept) in [(true, "/home/me/.claude"), (false, "/code/app/fake")] {
        let mut recorded = Recorded::load(&real).unwrap();
        unattended::record(&mut recorded, &planted, unattended);
        assert_eq!(recorded.dirs["claude-code"], Path::new(kept));
    }
    let mut empty = Recorded::default();
    unattended::record(&mut empty, &planted, true);
    assert_eq!(
        empty.dirs["claude-code"],
        Path::new("/code/app/fake"),
        "a host not recorded yet is recorded"
    );
}

#[test]
fn a_first_install_is_open_to_scripts_and_agents() {
    for interactive in [false, true] {
        assert_eq!(
            repin_checks(false, interactive),
            RepinChecks {
                agent: false,
                drift: false
            }
        );
    }
}

#[test]
fn a_re_pin_refuses_agents_and_without_a_terminal_drift() {
    assert_eq!(
        repin_checks(true, false),
        RepinChecks {
            agent: true,
            drift: true
        }
    );
    assert_eq!(
        repin_checks(true, true),
        RepinChecks {
            agent: true,
            drift: false
        }
    );
}

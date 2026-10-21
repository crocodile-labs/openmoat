use super::{RepinChecks, mcp, repin_checks};

#[test]
fn mcp_changes_over_an_existing_lock_wait_for_a_person() {
    assert!(mcp::hold_changes(true, false), "a detached script");
    assert!(!mcp::hold_changes(true, true), "a person at a terminal");
    assert!(!mcp::hold_changes(false, false), "a first install");
    assert!(!mcp::hold_changes(false, true));
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

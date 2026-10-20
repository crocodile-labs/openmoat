use super::{RepinChecks, repin_checks};

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

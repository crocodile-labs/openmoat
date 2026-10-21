//! Warnings about ports in `net` and `fetch` host patterns (docs/POLICY.md §5.2).
//!
//! `openmoat proxy` reaches a host on 443 and 80 unless a pattern names another
//! port as `host:port`. A port written any other way matches nothing, so the
//! rule does not do what it says.

use crate::host::malformed_port_pattern;
use crate::kind::Kind;
use crate::policy::Policy;

use super::Warning;

/// One warning per `net` or `fetch` pattern whose port is not one.
pub(super) fn malformed(policy: &Policy, out: &mut Vec<Warning>) {
    let groups = policy
        .deny
        .iter()
        .chain(&policy.allow)
        .chain(&policy.ask)
        .chain(&policy.defer);
    for group in groups {
        for kind in [Kind::Net, Kind::Fetch] {
            for pattern in group.patterns(kind) {
                if malformed_port_pattern(pattern) {
                    out.push(Warning {
                        rule: group.id.clone(),
                        message: format!(
                            "`{pattern}` names a port that is not one (1 to 65535, decimal \
                             digits only; no IPv6 address takes a port), so it matches nothing"
                        ),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lint::warnings;
    use crate::policy::Policy;

    #[test]
    fn a_port_that_is_not_one_is_reported() {
        let yaml = "version: 1\nallow:\n  - id: web\n    \
                    net: ['a.example.com:8443', 'b.example.com:*', 'fe80:*', '[fd00::5]:443']\n    \
                    fetch: ['c.example.com:0']\n";
        let shown: Vec<String> = warnings(&Policy::parse(yaml).unwrap())
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(shown.len(), 3, "{shown:?}");
        for pattern in ["b.example.com:*", "[fd00::5]:443", "c.example.com:0"] {
            assert!(
                shown.iter().any(|w| w.contains(pattern)),
                "{pattern}: {shown:?}"
            );
        }
    }
}

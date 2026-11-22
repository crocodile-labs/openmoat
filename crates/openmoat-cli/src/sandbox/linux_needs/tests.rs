use openmoat_hosts::Host;

use super::*;

/// A Linux machine where everything the hosts' sandboxes need is there.
fn fine() -> Facts {
    Facts {
        apparmor_restrict: Some("0".to_owned()),
        max_user_namespaces: Some("63000".to_owned()),
        unprivileged_clone: None,
        on_path: needed_programs().map(|p| p.name).collect(),
        bwrap: Some(Ok(())),
    }
}

/// The hosts whose spec names a Linux sandbox, from the specs.
fn with_needs() -> Vec<Host> {
    Host::ALL
        .into_iter()
        .filter(|h| needs(*h).is_some())
        .collect()
}

/// The hosts whose Linux sandbox starts this program.
fn needing(program: &str) -> Vec<Host> {
    with_needs()
        .into_iter()
        .filter(|h| needs(*h).is_some_and(|n| n.programs.iter().any(|p| p.name == program)))
        .collect()
}

#[test]
fn nothing_off_linux_and_nothing_on_a_machine_that_has_it_all() {
    if !cfg!(target_os = "linux") {
        assert_eq!(Facts::here(), None);
    }
    assert_eq!(user_namespaces(&fine()), None);
    assert_eq!(findings(&with_needs(), &fine()), Vec::new());
    assert_eq!(findings(&[], &Facts::default()), Vec::new());
}

/// The decision table: which facts block user namespaces, and what names it.
#[test]
fn which_facts_block_user_namespaces() {
    let blocked = |change: fn(&mut Facts)| {
        let mut facts = fine();
        change(&mut facts);
        user_namespaces(&facts)
    };
    // A bubblewrap that created its namespaces settles it, whatever AppArmor says
    // (a profile of its own allows them).
    assert_eq!(
        blocked(|f| f.apparmor_restrict = Some("1".to_owned())),
        None
    );
    // Without bubblewrap the settings decide.
    let apparmor = blocked(|f| {
        f.bwrap = None;
        f.apparmor_restrict = Some("1".to_owned());
    });
    assert_eq!(
        apparmor,
        Some(Blocked {
            setting: Some(Setting::AppArmor),
            bwrap: None
        })
    );
    assert_eq!(blocked(|f| f.bwrap = None), None);
    let max = blocked(|f| {
        f.bwrap = None;
        f.max_user_namespaces = Some("0".to_owned());
        f.apparmor_restrict = Some("1".to_owned());
    });
    assert_eq!(max.unwrap().setting, Some(Setting::MaxUserNamespaces));
    let debian = blocked(|f| {
        f.bwrap = None;
        f.apparmor_restrict = None;
        f.unprivileged_clone = Some("0".to_owned());
    });
    assert_eq!(debian.unwrap().setting, Some(Setting::UnprivilegedClone));
    assert_eq!(
        blocked(|f| {
            f.bwrap = None;
            f.unprivileged_clone = Some("1".to_owned());
        }),
        None
    );
    // bubblewrap failed: its message, with the setting that explains it.
    let refused = blocked(|f| {
        f.bwrap = Some(Err(
            "bwrap: setting up uid map: Permission denied".to_owned()
        ));
        f.apparmor_restrict = Some("1".to_owned());
    })
    .unwrap();
    assert_eq!(refused.setting, Some(Setting::AppArmor));
    assert!(refused.bwrap.unwrap().contains("uid map"));
    // No setting explains it (a container): bubblewrap's message alone.
    let container = blocked(|f| f.bwrap = Some(Err("bwrap: No permissions".to_owned()))).unwrap();
    assert_eq!(container.setting, None);
}

/// Blocked user namespaces stop every host whose spec says it needs them,
/// with what that host then does and the fixes; nothing is decided from it.
#[test]
fn blocked_user_namespaces_are_a_finding_per_host_that_needs_them() {
    let mut facts = fine();
    facts.bwrap = Some(Err(
        "bwrap: setting up uid map: Permission denied".to_owned()
    ));
    facts.apparmor_restrict = Some("1".to_owned());
    let hosts = with_needs();
    let found = findings(&hosts, &facts);
    let expected: Vec<&str> = hosts
        .iter()
        .filter(|h| needs(**h).is_some_and(|n| n.user_namespaces))
        .map(|h| h.id())
        .collect();
    assert_ne!(expected, Vec::<&str>::new());
    assert_eq!(found.iter().map(|f| f.host).collect::<Vec<_>>(), expected);
    for finding in &found {
        let line = finding.line();
        assert!(
            line.starts_with(&format!(
                "{:<16} the agent's own sandbox cannot start commands on this machine: ",
                finding.agent
            )),
            "{line}"
        );
        assert!(
            line.contains("apparmor_restrict_unprivileged_userns is 1"),
            "{line}"
        );
        assert!(line.contains("uid map"), "{line}");
        assert!(line.contains(needs_of(finding).without), "{line}");
        assert!(
            line.contains("`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`"),
            "{line}"
        );
        assert!(line.contains("/etc/sysctl.d/"), "{line}");
        assert!(line.contains("AppArmor profile"), "{line}");
        assert!(
            line.contains("no setting that leaves this agent's sandbox off"),
            "{line}"
        );
        assert_eq!(
            finding.short(),
            "own sandbox cannot start commands here: user namespaces are blocked"
        );
    }
    // The JSON fields `openmoat status` prints.
    let value = serde_json::to_value(&found[0]).unwrap();
    assert_eq!(value["user_namespaces"]["setting"], "apparmor");
    assert!(value["fixes"].as_array().unwrap().len() >= 2);
    assert_eq!(value["missing"], serde_json::json!([]));
}

fn needs_of(finding: &Finding) -> &'static LinuxSandboxNeeds {
    let host = Host::ALL
        .into_iter()
        .find(|h| h.id() == finding.host)
        .unwrap();
    needs(host).unwrap()
}

/// A program missing from the search path stops only the hosts that start it.
#[test]
fn a_missing_program_is_a_finding_for_the_hosts_that_start_it() {
    for program in needed_programs().map(|p| p.name) {
        let mut facts = fine();
        facts.on_path.retain(|p| *p != program);
        let found = findings(&with_needs(), &facts);
        let hosts: Vec<&str> = needing(program).iter().map(|h| h.id()).collect();
        assert_eq!(found.iter().map(|f| f.host).collect::<Vec<_>>(), hosts);
        for finding in &found {
            assert_eq!(finding.missing, vec![program]);
            assert_eq!(finding.user_namespaces, None);
            assert!(
                finding
                    .line()
                    .contains(&format!("{program} is not on PATH"))
            );
            assert!(
                finding.fixes[0].contains("sudo apt-get install"),
                "{:?}",
                finding.fixes
            );
            assert!(finding.short().contains(&format!("{program} not on PATH")));
        }
    }
}

#[test]
fn each_setting_has_its_own_fix() {
    let fix = |setting| {
        namespace_fixes(&Blocked {
            setting,
            bwrap: None,
        })
        .join("; or ")
    };
    assert!(fix(Some(Setting::UnprivilegedClone)).contains("kernel.unprivileged_userns_clone=1"));
    assert!(fix(Some(Setting::MaxUserNamespaces)).contains("user.max_user_namespaces above 0"));
    assert!(fix(None).contains("container or virtual machine"));
}

/// Which hosts have Linux needs is the specs' fact, not this module's: every
/// host with a sandbox states them.
#[test]
fn every_host_sandbox_states_its_linux_needs() {
    for host in crate::sandbox::install::hosts() {
        let needs = needs(host).unwrap_or_else(|| panic!("{} states no Linux needs", host.id()));
        assert_ne!(needs.without, "");
    }
}

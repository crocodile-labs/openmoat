use openmoat_hosts::Host;

use super::*;

/// A Linux machine where everything the hosts' sandboxes need is there.
fn fine() -> Facts {
    Facts {
        apparmor_restrict: Some("0".to_owned()),
        apparmor_restrict_unconfined: Some("0".to_owned()),
        bwrap_apparmor: Some(BwrapProfileSeen {
            profile: BwrapProfile::None,
            seen: Seen::Loaded,
        }),
        bwrap_path: Some(PathBuf::from(USR_BIN_BWRAP)),
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
        // Each agent's own documented fix, from its spec.
        let own = match needs_of(finding).apparmor {
            UsernsProfileFix::UnconfinedBwrapProfile => "flags=(unconfined) { userns, }",
            UsernsProfileFix::BwrapUsernsRestrict => "load Ubuntu's bwrap-userns-restrict",
            UsernsProfileFix::OwnPackage(package) => package,
            _ => unreachable!(),
        };
        assert!(line.contains(own), "{line}");
        assert_eq!(finding.bwrap_userns_restrict, None);
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
        namespace_fixes(
            &Blocked {
                setting,
                bwrap: None,
            },
            UsernsProfileFix::BwrapUsernsRestrict,
            true,
        )
        .join("; or ")
    };
    assert!(fix(Some(Setting::UnprivilegedClone)).contains("kernel.unprivileged_userns_clone=1"));
    assert!(fix(Some(Setting::MaxUserNamespaces)).contains("user.max_user_namespaces above 0"));
    assert!(fix(None).contains("container or virtual machine"));
}

/// The `AppArmor` fixes per agent's documentation: Claude Code's profile only
/// for `/usr/bin/bwrap` (else the `sysctl` alone), and never
/// `bwrap-userns-restrict` for it.
#[test]
fn the_apparmor_fix_is_the_agents_own() {
    let apparmor = Blocked {
        setting: Some(Setting::AppArmor),
        bwrap: None,
    };
    let claude = namespace_fixes(&apparmor, UsernsProfileFix::UnconfinedBwrapProfile, true);
    assert_eq!(claude.len(), 2);
    assert!(claude[0].contains("/etc/apparmor.d/bwrap ("), "{claude:?}");
    assert!(
        claude[0].contains("profile bwrap /usr/bin/bwrap flags=(unconfined) { userns, }"),
        "{claude:?}"
    );
    assert!(
        !claude.join(" ").contains("bwrap-userns-restrict"),
        "{claude:?}"
    );
    assert!(claude[1].contains("apparmor_restrict_unprivileged_userns=0"));
    let elsewhere = namespace_fixes(&apparmor, UsernsProfileFix::UnconfinedBwrapProfile, false);
    assert_eq!(elsewhere.len(), 1);
    assert!(elsewhere[0].starts_with("`sudo sysctl -w"), "{elsewhere:?}");
    let codex = namespace_fixes(&apparmor, UsernsProfileFix::BwrapUsernsRestrict, true);
    assert!(
        codex[0].contains("/usr/share/apparmor/extra-profiles/bwrap-userns-restrict"),
        "{codex:?}"
    );
    let cursor = namespace_fixes(&apparmor, UsernsProfileFix::OwnPackage("pkg-x"), true);
    assert!(cursor[0].contains("pkg-x"), "{cursor:?}");
}

/// The facts of GitHub's `ubuntu-latest` runner (#784): bubblewrap creates its
/// namespaces, the restriction is lifted, and `bwrap-userns-restrict` is
/// loaded. Only the hosts whose documentation gives the unconfined profile
/// fail, with that profile as the fix and no `sysctl`.
#[test]
fn bwrap_userns_restrict_breaks_only_the_hosts_that_document_an_unconfined_profile() {
    let mut facts = fine();
    facts.apparmor_restrict_unconfined = Some("1".to_owned());
    facts.bwrap_apparmor = Some(BwrapProfileSeen {
        profile: BwrapProfile::UsernsRestrict,
        seen: Seen::Loaded,
    });
    assert_eq!(user_namespaces(&facts), None);
    let found = findings(&with_needs(), &facts);
    let expected: Vec<&str> = with_needs()
        .into_iter()
        .filter(|h| {
            needs(*h).is_some_and(|n| n.apparmor == UsernsProfileFix::UnconfinedBwrapProfile)
        })
        .map(Host::id)
        .collect();
    assert_ne!(expected, Vec::<&str>::new());
    assert!(expected.len() < with_needs().len(), "{expected:?}");
    assert_eq!(found.iter().map(|f| f.host).collect::<Vec<_>>(), expected);
    for finding in &found {
        let line = finding.line();
        assert!(
            line.contains("bwrap-userns-restrict AppArmor profile is loaded"),
            "{line}"
        );
        assert!(
            line.contains("apparmor_restrict_unprivileged_unconfined at 1"),
            "{line}"
        );
        assert!(line.contains("/proc/self/setgroups"), "{line}");
        assert!(line.contains("/etc/apparmor.d/disable/"), "{line}");
        assert!(line.contains("flags=(unconfined) { userns, }"), "{line}");
        assert!(line.contains("alone does not help"), "{line}");
        assert!(!line.contains("sudo sysctl -w"), "{line}");
        assert_eq!(finding.fixes.len(), 1);
        assert!(finding.short().contains("bwrap-userns-restrict"));
        let value = serde_json::to_value(finding).unwrap();
        assert_eq!(value["bwrap_userns_restrict"]["seen"], "loaded");
    }
    // Under the restriction too: the profile's fix replaces the setting's.
    facts.apparmor_restrict = Some("1".to_owned());
    facts.bwrap = Some(Err(
        "bwrap: setting up uid map: Permission denied".to_owned()
    ));
    for finding in findings(&with_needs(), &facts) {
        if finding.bwrap_userns_restrict.is_some() {
            assert_eq!(finding.fixes.len(), 1, "{:?}", finding.fixes);
        }
    }
    // Not where the agent runs another bwrap, nor where the documented profile
    // or none applies, nor where it cannot be read.
    for change in [
        (|f: &mut Facts| f.bwrap_path = Some(PathBuf::from("/opt/bin/bwrap"))) as fn(&mut Facts),
        |f| f.bwrap_apparmor = None,
        |f| {
            f.bwrap_apparmor = Some(BwrapProfileSeen {
                profile: BwrapProfile::Unconfined,
                seen: Seen::Installed,
            });
        },
    ] {
        let mut facts = fine();
        facts.bwrap_apparmor = Some(BwrapProfileSeen {
            profile: BwrapProfile::UsernsRestrict,
            seen: Seen::Installed,
        });
        change(&mut facts);
        assert_eq!(findings(&with_needs(), &facts), Vec::new());
    }
}

#[test]
fn the_profile_for_bwrap_from_the_kernels_list() {
    use apparmor::from_loaded;
    assert_eq!(from_loaded(""), BwrapProfile::None);
    assert_eq!(
        from_loaded("unpriv_bwrap (enforce)\nbwrap (enforce)\nfirefox (unconfined)\n"),
        BwrapProfile::UsernsRestrict
    );
    // The documented profile replaced Ubuntu's `bwrap`; `unpriv_bwrap` lingers.
    assert_eq!(
        from_loaded("bwrap (unconfined)\nunpriv_bwrap (enforce)\n"),
        BwrapProfile::Unconfined
    );
    assert_eq!(from_loaded("bwrap (complain)\n"), BwrapProfile::Other);
    assert_eq!(from_loaded("unpriv_bwrap (enforce)\n"), BwrapProfile::None);
    assert_eq!(from_loaded("bwrap2 (enforce)\n"), BwrapProfile::None);
}

#[test]
fn the_profile_for_bwrap_from_the_installed_files() {
    use apparmor::from_installed;
    let names = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let documented =
        "abi <abi/4.0>,\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n";
    assert_eq!(
        from_installed(&names(&["bwrap-userns-restrict", "firefox"]), &[], None),
        BwrapProfile::UsernsRestrict
    );
    // Disabled the way Ubuntu's AppArmor documentation disables a profile.
    assert_eq!(
        from_installed(
            &names(&["bwrap-userns-restrict", "bwrap"]),
            &names(&["bwrap-userns-restrict"]),
            Some(documented)
        ),
        BwrapProfile::Unconfined
    );
    // Both installed: both define `bwrap`; the fix is the same.
    assert_eq!(
        from_installed(
            &names(&["bwrap-userns-restrict", "bwrap"]),
            &[],
            Some(documented)
        ),
        BwrapProfile::UsernsRestrict
    );
    assert_eq!(
        from_installed(
            &names(&["bwrap"]),
            &[],
            Some("profile bwrap /usr/bin/bwrap {}")
        ),
        BwrapProfile::Other
    );
    assert_eq!(
        from_installed(&names(&["firefox"]), &[], None),
        BwrapProfile::None
    );
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

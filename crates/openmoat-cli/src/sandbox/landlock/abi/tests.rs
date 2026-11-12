use super::*;

#[test]
fn the_steps_run_from_the_floor_up_one_abi_at_a_time() {
    let abis: Vec<u32> = STEPS.iter().map(|s| s.abi).collect();
    assert_eq!(abis, (FLOOR..FLOOR + 9).collect::<Vec<_>>());
    assert_eq!(STEPS[0].used, Use::Required);
    assert!(STEPS[1..].iter().all(|s| s.used != Use::Required));
}

#[test]
fn a_kernel_below_the_floor_or_without_landlock_is_refused() {
    for kernel in [
        Kernel::Abi(3),
        Kernel::Missing("not enabled at boot".to_owned()),
    ] {
        assert!(!kernel.meets_floor());
        assert_eq!(kernel.applied(), Vec::<u32>::new());
        assert!(summary(&kernel).contains("refuses to start"), "{kernel:?}");
    }
    assert!(summary(&Kernel::Missing("no Landlock".to_owned())).contains("(no Landlock)"));
}

/// Today's behaviour on a kernel older than every new step: the floor and the
/// scopes, and the seccomp filter named for what the newer steps would add.
#[test]
fn an_older_kernel_applies_what_it_has_and_names_the_seccomp_fallback() {
    let six = Kernel::Abi(6);
    assert_eq!(six.applied(), [4, 6]);
    let shown = summary(&six);
    assert!(shown.contains("applies ABI 4, 6"), "{shown}");
    assert!(shown.contains("seccomp filter alone"), "{shown}");
    assert!(shown.contains("ABI 9 (Linux 7.1)"), "{shown}");
    let lines = lines(&six);
    let nine = lines.iter().find(|l| l.starts_with("ABI 9 ")).unwrap();
    assert!(nine.contains("not available here"), "{nine}");
    assert!(nine.contains("no datagram socket pair"), "{nine}");
    let four = lines.iter().find(|l| l.starts_with("ABI 4 ")).unwrap();
    assert!(four.contains("used:"), "{four}");
}

#[test]
fn the_floor_alone_applies_only_the_floor() {
    assert_eq!(Kernel::Abi(4).applied(), [4]);
    assert_eq!(Kernel::Abi(5).applied(), [4]);
}

#[test]
fn a_new_kernel_applies_the_unix_socket_step_and_names_what_it_leaves() {
    let twelve = Kernel::Abi(12);
    assert_eq!(twelve.applied(), [4, 6, 9]);
    let shown = summary(&twelve);
    assert!(!shown.contains("seccomp filter alone"), "{shown}");
    let lines = lines(&twelve);
    assert_eq!(lines.len(), STEPS.len());
    let udp = lines.iter().find(|l| l.starts_with("ABI 10 ")).unwrap();
    assert!(udp.contains("available, not used"), "{udp}");
    assert!(udp.contains("refuses UDP sockets"), "{udp}");
    let tsync = lines.iter().find(|l| l.starts_with("ABI 8 ")).unwrap();
    assert!(tsync.contains("proxy and relay threads"), "{tsync}");
}

#[test]
fn a_kernel_newer_than_the_table_says_so() {
    let lines = lines(&Kernel::Abi(14));
    assert_eq!(lines.len(), STEPS.len() + 1);
    assert!(lines.last().unwrap().contains("ABI 14 here is newer"));
}

/// Every step's fallback names what holds without it, and no step that is
/// not applied claims to protect anything.
#[test]
fn every_step_says_what_holds_without_it() {
    for step in STEPS {
        assert!(!step.without.is_empty(), "ABI {}", step.abi);
        assert!(!step.why.is_empty(), "ABI {}", step.abi);
        assert!(
            step.adds.contains('`'),
            "ABI {} names the kernel's flag",
            step.abi
        );
    }
}

#[test]
fn the_json_carries_the_kernel_the_applied_steps_and_the_table() {
    let value = json(&Kernel::Abi(9));
    assert_eq!(value["kernel"]["abi"], 9);
    assert_eq!(value["floor"], FLOOR);
    assert_eq!(value["applied"], serde_json::json!([4, 6, 9]));
    assert_eq!(value["steps"][5]["used"], "used");
    assert_eq!(value["steps"][6]["used"], "not_in_crate");
    let missing = json(&Kernel::Missing("no Landlock".to_owned()));
    assert_eq!(missing["kernel"]["missing"], "no Landlock");
}

//! The microVM tier's protection score (ADR-128). Its boundary is of another
//! kind than a sandbox on the host's kernel, so it has a table of its own
//! (a score compares runs of one platform and tier, ADR-108). The tier is a
//! design: no feature is built, so it scores 0 with every feature named.

use super::{Mechanism, ProtectionScore, ScoreItem};

/// The weights of the microVM tier, adding up to 100: the kernel of its own
/// first, then the network, what the guest sees, the hook's way to the guard
/// and the image's digests.
pub const WEIGHTS_VM: [(Mechanism, u32); 5] = [
    (Mechanism::VmHypervisor, 35),
    (Mechanism::VmProxyNetwork, 25),
    (Mechanism::VmProjectOnly, 20),
    (Mechanism::VmGuardRelay, 10),
    (Mechanism::VmImagePinned, 10),
];

/// Whether `name` is one of the microVM tier's features.
pub(super) fn is_vm(name: Mechanism) -> bool {
    WEIGHTS_VM.iter().any(|(m, _)| *m == name)
}

/// What brings `name`.
pub(super) fn needs(name: Mechanism) -> &'static str {
    match name {
        Mechanism::VmHypervisor => {
            "a VM monitor: Virtualization.framework (macOS 12 or later), or Firecracker or \
             cloud-hypervisor on KVM (Linux, `/dev/kvm`)"
        }
        Mechanism::VmProxyNetwork => "a guest with no network device and a vsock port to the proxy",
        Mechanism::VmProjectOnly => {
            "the project shared into the guest by virtiofs, and nothing else"
        }
        Mechanism::VmGuardRelay => "the guest's hook client reaching the guard relay over vsock",
        Mechanism::VmImagePinned => {
            "`sandbox.vm.image` in your policy, each digest checked at boot"
        }
        _ => "",
    }
}

/// The microVM tier's score on a system whose VM monitor is `monitor` (or
/// why there is none): every feature not built yet, named with what it
/// needs, and the system's lack of a monitor named too.
#[must_use]
pub fn vm_score(monitor: Result<&str, &str>) -> ProtectionScore {
    let items = WEIGHTS_VM
        .iter()
        .map(|&(name, weight)| {
            let mut missing = format!("not built yet (ADR-128): {}", needs(name));
            if let (Mechanism::VmHypervisor, Err(why)) = (name, monitor) {
                missing.push_str("; this system has none: ");
                missing.push_str(why);
            }
            ScoreItem {
                name,
                weight,
                in_force: false,
                missing: Some(missing),
            }
        })
        .collect();
    ProtectionScore { points: 0, items }
}

#[cfg(test)]
mod tests {
    use super::{WEIGHTS_VM, vm_score};

    #[test]
    fn the_vm_table_adds_up_to_100_and_scores_nothing_until_built() {
        assert_eq!(WEIGHTS_VM.iter().map(|(_, w)| w).sum::<u32>(), 100);
        let score = vm_score(Ok("KVM"));
        assert_eq!(score.points, 0);
        assert!(!score.complete());
        assert_eq!(score.missing().len(), 5);
        assert!(
            score
                .line()
                .starts_with("0/100; missing: vm_hypervisor (not built yet")
        );
        let none = vm_score(Err("no /dev/kvm"));
        assert!(none.missing()[0].contains("this system has none: no /dev/kvm"));
        assert!(!vm_score(Ok("KVM")).missing()[0].contains("has none"));
    }
}

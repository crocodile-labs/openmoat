//! The kernel's Landlock ABI (ADR-082), read without restricting anything:
//! `landlock_restrict_self` with no flag is skipped by the crate, and
//! `no_new_privs` is not set, so this process stays as it was.

use landlock::{LandlockStatus, RestrictSelf};

use crate::sandbox::landlock::abi::Kernel;

/// The running kernel's Landlock ABI, also where it is newer than the
/// `landlock` crate knows.
pub fn kernel() -> Kernel {
    match RestrictSelf::default().no_new_privs(false).apply() {
        Ok(status) => from_status(status.landlock),
        Err(error) => Kernel::Missing(format!("reading the Landlock ABI: {error}")),
    }
}

/// The kernel's ABI as a Landlock status gives it: the probe's, and the one
/// `restrict_self` reports when the agent starts (`launch.rs`).
pub(super) fn from_status(status: LandlockStatus) -> Kernel {
    match status {
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => Kernel::Abi(
            kernel_abi
                .and_then(|abi| u32::try_from(abi).ok())
                .unwrap_or(effective_abi as u32),
        ),
        LandlockStatus::NotEnabled => Kernel::Missing(
            "the kernel has Landlock but it is not enabled at boot (add `landlock` to the \
             `lsm=` kernel parameter)"
                .to_owned(),
        ),
        LandlockStatus::NotImplemented => {
            Kernel::Missing("the kernel is built without Landlock".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use landlock::ABI;

    use super::*;
    use crate::sandbox::landlock::abi::{STEPS, Use};

    /// The ladder's "used" steps are ones the crate can ask for, and its
    /// "not in the crate" steps are past the newest ABI the crate knows: when
    /// the crate learns one, this fails until the ladder (and ADR-082) moves.
    #[test]
    fn the_ladder_matches_the_landlock_crate() {
        let newest = ABI::from(i32::MAX) as u32;
        for step in STEPS {
            match step.used {
                Use::Required | Use::Used => assert!(step.abi <= newest, "ABI {}", step.abi),
                Use::NotInCrate => assert!(step.abi > newest, "ABI {} is in the crate", step.abi),
                Use::NotUsed => {}
            }
        }
    }

    #[test]
    fn the_status_maps_to_the_kernels_abi() {
        let newer = LandlockStatus::Available {
            effective_abi: ABI::V9,
            kernel_abi: Some(12),
        };
        assert_eq!(from_status(newer), Kernel::Abi(12));
        let known = LandlockStatus::Available {
            effective_abi: ABI::V6,
            kernel_abi: None,
        };
        assert_eq!(from_status(known), Kernel::Abi(6));
        assert!(matches!(
            from_status(LandlockStatus::NotEnabled),
            Kernel::Missing(why) if why.contains("lsm=")
        ));
    }

    /// The probe leaves this thread unrestricted and without `no_new_privs`.
    #[test]
    fn reading_the_abi_restricts_nothing() {
        let before = std::fs::read_to_string("/proc/thread-self/status").unwrap_or_default();
        let kernel = kernel();
        let after = std::fs::read_to_string("/proc/thread-self/status").unwrap_or_default();
        let nnp = |s: &str| {
            s.lines()
                .find(|l| l.starts_with("NoNewPrivs:"))
                .map(str::to_owned)
        };
        assert_eq!(nnp(&before), nnp(&after), "{kernel:?}");
        assert!(std::fs::read_to_string("/proc/self/status").is_ok());
    }
}

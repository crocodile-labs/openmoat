//! The policy's `sandbox.vm:` section (ADR-128): the guest image the
//! microVM tier of `openmoat run` would boot, and its size. The tier is a
//! design: `openmoat run --vm` refuses on every system. The section is read
//! and checked now, so a definition written today means the same once the
//! tier boots.
//!
//! OpenMoat downloads no image. The person names local files with their
//! SHA-256 digests; the run would check each digest before the boot.

use serde::{Deserialize, Serialize};

use crate::policy::PolicyError;

/// The smallest and largest guest memory, in MiB.
pub const MEMORY_MIB: (u32, u32) = (256, 65_536);
/// The most virtual CPUs.
pub const MAX_CPUS: u8 = 64;
/// The guest memory when none is given, in MiB.
pub const DEFAULT_MEMORY_MIB: u32 = 2048;
/// The virtual CPUs when none is given.
pub const DEFAULT_CPUS: u8 = 2;

/// Kernel parameters a `cmdline` may not set: OpenMoat's own init must be the
/// guest's first process, since it mounts the project and serves the proxy
/// and guard ports.
const RESERVED_PARAMETERS: &[&str] = &["init=", "rdinit="];

/// `sandbox.vm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmSettings {
    /// The guest's kernel, root image and optional initial RAM disk.
    pub image: VmImage,
    /// Guest memory in MiB, 256 to 65536; [`DEFAULT_MEMORY_MIB`] when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u32>,
    /// Virtual CPUs, 1 to 64; [`DEFAULT_CPUS`] when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u8>,
}

/// `sandbox.vm.image`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmImage {
    /// The guest kernel (an uncompressed `vmlinux` for Firecracker, an `Image`
    /// for Virtualization.framework on Apple silicon).
    pub kernel: VmFile,
    /// The read-only root file system image.
    pub rootfs: VmFile,
    /// An initial RAM disk, if the image needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd: Option<VmFile>,
    /// Kernel parameters appended to OpenMoat's own; never `init=` or
    /// `rdinit=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
}

/// One file of the image and the digest it must have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmFile {
    /// Absolute or `~/…`, no glob.
    pub path: String,
    /// The file's SHA-256, 64 lowercase hexadecimal digits.
    pub sha256: String,
}

impl VmSettings {
    /// Guest memory in MiB.
    #[must_use]
    pub fn memory_mib(&self) -> u32 {
        self.memory_mib.unwrap_or(DEFAULT_MEMORY_MIB)
    }

    /// Virtual CPUs.
    #[must_use]
    pub fn cpus(&self) -> u8 {
        self.cpus.unwrap_or(DEFAULT_CPUS)
    }

    /// The image's files with what each is, for messages.
    #[must_use]
    pub fn files(&self) -> Vec<(&'static str, &VmFile)> {
        let mut out = vec![
            ("kernel", &self.image.kernel),
            ("rootfs", &self.image.rootfs),
        ];
        if let Some(initrd) = &self.image.initrd {
            out.push(("initrd", initrd));
        }
        out
    }
}

/// Every file is absolute or under `~/` with a well-formed digest, memory and
/// CPUs are in range, and `cmdline` sets no reserved parameter and holds no
/// control character.
pub(crate) fn check(settings: Option<&VmSettings>) -> Result<(), PolicyError> {
    let Some(vm) = settings else {
        return Ok(());
    };
    let bad = |field: &str, problem: String| PolicyError::Rule {
        rule: format!("sandbox.vm.{field}"),
        problem,
    };
    for (name, file) in vm.files() {
        let rooted = file.path.starts_with('/') || file.path.starts_with("~/");
        if !rooted || file.path.contains(['*', '?', '[', '{']) || file.path.contains("/../") {
            return Err(bad(
                &format!("image.{name}.path"),
                format!(
                    "`{}` must be an absolute or `~/` path to one file, without a glob or `..`",
                    file.path
                ),
            ));
        }
        let hex = file.sha256.len() == 64
            && file
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex {
            return Err(bad(
                &format!("image.{name}.sha256"),
                "must be the file's SHA-256 as 64 lowercase hexadecimal digits \
                 (`shasum -a 256 <file>`)"
                    .to_owned(),
            ));
        }
    }
    let memory = vm.memory_mib();
    if !(MEMORY_MIB.0..=MEMORY_MIB.1).contains(&memory) {
        return Err(bad(
            "memory_mib",
            format!("{memory} is outside {} to {}", MEMORY_MIB.0, MEMORY_MIB.1),
        ));
    }
    if !(1..=MAX_CPUS).contains(&vm.cpus()) {
        return Err(bad(
            "cpus",
            format!("{} is outside 1 to {MAX_CPUS}", vm.cpus()),
        ));
    }
    if let Some(cmdline) = &vm.image.cmdline {
        if cmdline.chars().any(char::is_control) {
            return Err(bad("image.cmdline", "holds a control character".to_owned()));
        }
        let reserved = cmdline
            .split_whitespace()
            .find(|word| RESERVED_PARAMETERS.iter().any(|p| word.starts_with(p)));
        if let Some(word) = reserved {
            return Err(bad(
                "image.cmdline",
                format!("`{word}`: OpenMoat's own init must be the guest's first process"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::policy::{Policy, PolicyError};

    const KERNEL: &str = "kernel: { path: ~/vm/vmlinux, sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef }";
    const ROOTFS: &str = "rootfs: { path: /opt/vm/rootfs.ext4, sha256: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 }";

    fn with(image_extra: &str, vm_extra: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&format!(
            "version: 1\nsandbox:\n  vm:\n    image:\n      {KERNEL}\n      {ROOTFS}\n{image_extra}{vm_extra}"
        ))
    }

    fn rule_of(result: Result<Policy, PolicyError>) -> String {
        match result {
            Err(PolicyError::Rule { rule, .. }) => rule,
            other => panic!("expected a rule error, got {other:?}"),
        }
    }

    #[test]
    fn a_pinned_image_reads_with_its_defaults() {
        let policy = with("", "").unwrap();
        let vm = policy.sandbox.unwrap().vm.unwrap();
        assert_eq!((vm.memory_mib(), vm.cpus()), (2048, 2));
        assert_eq!(vm.files().len(), 2);
    }

    #[test]
    fn bad_paths_digests_sizes_and_kernel_parameters_are_refused() {
        let bad_kernel = |path: &str, sha: &str| {
            Policy::parse(&format!(
                "version: 1\nsandbox:\n  vm:\n    image:\n      kernel: {{ path: '{path}', sha256: '{sha}' }}\n      {ROOTFS}\n"
            ))
        };
        let good = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            rule_of(bad_kernel("vm/vmlinux", good)),
            "sandbox.vm.image.kernel.path"
        );
        assert_eq!(
            rule_of(bad_kernel("/vm/*", good)),
            "sandbox.vm.image.kernel.path"
        );
        assert_eq!(
            rule_of(bad_kernel("/a/../etc/x", good)),
            "sandbox.vm.image.kernel.path"
        );
        assert_eq!(
            rule_of(bad_kernel("/vm/k", "ABC")),
            "sandbox.vm.image.kernel.sha256"
        );
        assert_eq!(
            rule_of(bad_kernel("/vm/k", &good.to_uppercase())),
            "sandbox.vm.image.kernel.sha256"
        );
        assert_eq!(
            rule_of(with("", "    memory_mib: 64\n")),
            "sandbox.vm.memory_mib"
        );
        assert_eq!(rule_of(with("", "    cpus: 0\n")), "sandbox.vm.cpus");
        assert_eq!(
            rule_of(with("      cmdline: 'quiet init=/bin/sh'\n", "")),
            "sandbox.vm.image.cmdline"
        );
        assert_eq!(
            rule_of(with("      cmdline: 'rdinit=/x'\n", "")),
            "sandbox.vm.image.cmdline"
        );
        assert!(with("      cmdline: 'quiet loglevel=3'\n", "").is_ok());
    }
}

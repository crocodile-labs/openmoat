//! `openmoat run --vm` (ADR-128): the microVM tier, a design. It refuses on
//! every system (exit 64), never falling back to another tier: a person who
//! asked for a VM must not get less without being told. The refusal says
//! what this system would use (its VM monitor, or why it has none), what the
//! policy's `sandbox.vm` names, and the tier's score, 0 with every feature
//! named, so the flag already answers "what would I get here".

use std::fmt::Write as _;

use openmoat_core::boundary::vm_score;
use openmoat_core::vm::VmSettings;

use crate::exit::Code;
use crate::home::Home;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod other;

#[cfg(target_os = "linux")]
use linux as host;
#[cfg(target_os = "macos")]
use macos as host;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use other as host;

/// Where the tier is explained.
const DOCS: &str = "docs/SANDBOX.md \"The microVM tier (design)\"";

/// Refuse the run, saying why and what this system would use.
pub fn refuse() -> Code {
    // Read only, and only to name the image: a policy that cannot be read
    // changes nothing about the refusal.
    let vm = Home::locate()
        .ok()
        .and_then(|home| home.load_policy().ok())
        .and_then(|policy| policy.sandbox.and_then(|s| s.vm));
    eprint!("{}", message(&host::monitor(), vm.as_ref()));
    Code::Usage
}

/// The refusal for a system whose VM monitor is `monitor` (or why it has
/// none) and a policy whose `sandbox.vm` is `vm`.
pub(super) fn message(monitor: &Result<String, String>, vm: Option<&VmSettings>) -> String {
    let mut out = String::from(
        "openmoat run --vm: the microVM tier is a design (ADR-128) and cannot start an agent \
         yet; nothing was started.\n",
    );
    let _ = match monitor {
        Ok(name) => writeln!(out, "  this system would use: {name}"),
        Err(why) => writeln!(
            out,
            "  this system has no VM monitor the tier would use: {why}"
        ),
    };
    match vm {
        Some(vm) => {
            let files: Vec<String> = vm
                .files()
                .iter()
                .map(|(what, file)| {
                    let short = file.sha256.get(..12).unwrap_or(&file.sha256);
                    format!("{what} {} (sha256 {short}…)", file.path)
                })
                .collect();
            let _ = writeln!(
                out,
                "  sandbox.vm.image: {}; {} MiB, {} CPUs",
                files.join(", "),
                vm.memory_mib(),
                vm.cpus()
            );
        }
        None => {
            let _ = writeln!(
                out,
                "  sandbox.vm: not set in your policy (the image to boot)"
            );
        }
    }
    let monitor = monitor.as_deref().map_err(String::as_str);
    let _ = writeln!(out, "  score: {}", vm_score(monitor).line());
    let _ = writeln!(
        out,
        "Use `openmoat run -- <agent>` for the OS sandbox (`openmoat doctor` shows its score). Docs: {DOCS}"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::message;

    #[test]
    fn the_refusal_names_the_monitor_the_image_and_the_score() {
        let text = message(&Err("no /dev/kvm".to_owned()), None);
        assert!(text.contains("cannot start an agent yet"), "{text}");
        assert!(
            text.contains("has no VM monitor the tier would use: no /dev/kvm"),
            "{text}"
        );
        assert!(text.contains("sandbox.vm: not set"), "{text}");
        assert!(
            text.contains("score: 0/100; missing: vm_hypervisor"),
            "{text}"
        );
        assert!(text.contains("openmoat run -- <agent>"), "{text}");
        assert!(text.contains("docs/SANDBOX.md"), "{text}");
        let policy = openmoat_core::Policy::parse(
            "version: 1\nsandbox:\n  vm:\n    cpus: 4\n    image:\n      kernel: { path: ~/vm/vmlinux, sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef }\n      rootfs: { path: ~/vm/rootfs.ext4, sha256: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 }\n",
        )
        .unwrap();
        let vm = policy.sandbox.unwrap().vm.unwrap();
        let text = message(&Ok("KVM".to_owned()), Some(&vm));
        assert!(text.contains("this system would use: KVM"), "{text}");
        assert!(
            text.contains("kernel ~/vm/vmlinux (sha256 0123456789ab…)"),
            "{text}"
        );
        assert!(text.contains("2048 MiB, 4 CPUs"), "{text}");
    }
}

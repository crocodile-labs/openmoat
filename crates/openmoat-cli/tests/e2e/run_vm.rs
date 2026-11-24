//! `openmoat run --vm` (ADR-128): the microVM tier is a design, so the flag
//! refuses on every system with exit 64, starts nothing, and names what this
//! system would use, the policy's image and the tier's score.

use crate::common::{Sandbox, USAGE, stderr, text};
use crate::hosts::dir_of;
use openmoat_hosts::Host;

#[test]
fn the_vm_tier_refuses_and_names_what_this_system_would_use() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    let marker = sb.home.join("started");
    let marker = marker.to_string_lossy().into_owned();
    let out = sb.moat(&["run", "--vm", "--", "touch", &marker]);
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    let err = stderr(&out);
    assert!(err.contains("cannot start an agent yet"), "{err}");
    assert!(
        err.contains("score: 0/100; missing: vm_hypervisor"),
        "{err}"
    );
    assert!(err.contains("sandbox.vm: not set"), "{err}");
    assert!(err.contains("docs/SANDBOX.md"), "{err}");
    assert!(!std::path::Path::new(&marker).exists(), "nothing may start");
}

#[test]
fn the_vm_tier_is_not_combined_with_another_tier() {
    let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
    for other in ["--isolate", "--no-isolate"] {
        let out = sb.moat(&["run", "--vm", other, "--", "true"]);
        assert_eq!(out.status.code(), Some(USAGE), "{other}: {}", text(&out));
    }
}

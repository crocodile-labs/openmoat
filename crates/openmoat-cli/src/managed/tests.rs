use std::path::Path;

use openmoat_hosts::{Host, Platform};
use serde_json::json;

use super::command::{install_command, remove_command};
use super::{empty, hooks_of, on_this_platform};

#[test]
fn a_document_of_nothing_but_a_version_is_empty() {
    assert!(empty(&json!({})));
    assert!(empty(&json!({"version": 1, "hooks": {"preToolUse": []}})));
    assert!(empty(&json!({"hooks": {"PreToolUse": [{"hooks": []}]}})));
    assert!(!empty(
        &json!({"hooks": {"PreToolUse": [{"command": "lint"}]}})
    ));
    assert!(!empty(&json!({"version": "1"})));
    assert!(!empty(&json!({"disableAllHooks": true})));
    assert!(!empty(&json!({"permissions": {"deny": ["Read(.env)"]}})));
}

/// Each host OpenMoat writes a managed file for reads one on every platform
/// it runs on, and nowhere a platform has two.
#[test]
fn every_managed_host_has_one_file_per_platform() {
    for host in Host::ALL {
        let Some(hooks) = hooks_of(host) else {
            continue;
        };
        for platform in [
            Platform::MacOs,
            Platform::Linux,
            Platform::Wsl,
            Platform::Windows,
        ] {
            let count = hooks
                .files
                .iter()
                .filter(|f| f.platforms.contains(&platform))
                .count();
            assert_eq!(count, 1, "{host:?} on {platform:?}");
            assert!(on_this_platform(hooks.files, platform).is_some());
        }
    }
}

#[test]
fn the_install_command_quotes_every_path_and_never_runs_itself() {
    let staged = Path::new("/home/a b/.moat/managed/it's.json");
    let target = Path::new("/etc/x/policy.d/openmoat.json");
    let unix = install_command(staged, target, Platform::Linux);
    assert_eq!(
        unix,
        "sudo install -d -m 755 '/etc/x/policy.d' && sudo install -m 644 -o 0 -g 0 \
         '/home/a b/.moat/managed/it'\\''s.json' '/etc/x/policy.d/openmoat.json'"
    );
    let windows = install_command(
        Path::new("C:/Users/o'k/.moat/managed/x.json"),
        Path::new("C:/ProgramData/X/policy.d/openmoat.json"),
        Platform::Windows,
    );
    assert!(
        windows.contains("'C:/Users/o''k/.moat/managed/x.json'"),
        "{windows}"
    );
    assert!(
        windows.starts_with("in an elevated PowerShell"),
        "{windows}"
    );
    assert_eq!(
        remove_command(target, Platform::MacOs),
        "sudo rm -f '/etc/x/policy.d/openmoat.json'"
    );
}

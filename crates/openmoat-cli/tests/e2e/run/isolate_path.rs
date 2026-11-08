//! `openmoat run --isolate` and the `bwrap` it starts.

use std::path::Path;

use super::installed_with_secret;
use crate::common::{USAGE, output, stderr, text};

/// bubblewrap starts unconfined, so it comes from the system's directories,
/// never from `PATH`: a `bwrap` the project ships on a relative entry does
/// not run. Without a system one the agent does not start at all.
#[test]
fn isolate_never_runs_a_bwrap_from_path() {
    use std::os::unix::fs::PermissionsExt as _;

    let (sb, project) = installed_with_secret();
    let marker = project.join("project-bwrap-ran");
    let fake = project.join("bin/bwrap");
    std::fs::create_dir_all(project.join("bin")).unwrap();
    std::fs::write(&fake, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = output(
        sb.command()
            .current_dir(&project)
            .env("PATH", "bin:/usr/bin:/bin")
            .args(["run", "--isolate", "--", "/bin/sh", "-c", "echo ran"]),
        None,
    );
    assert!(!marker.exists(), "the project's bwrap ran: {}", text(&out));
    let system = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];
    if !system.iter().any(|p| Path::new(p).exists()) {
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(stderr(&out).contains("needs bubblewrap"), "{}", text(&out));
    }
}

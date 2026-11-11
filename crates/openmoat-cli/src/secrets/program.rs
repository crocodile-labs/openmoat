//! Whether the agent could change a `command` source's program (ADR-087).
//!
//! The program runs as the person, outside every sandbox, and its answer goes
//! into requests: a program the agent can replace is the agent's code. So it is
//! run only when both the path the policy names and the file it resolves to
//! are either
//!
//! - kept from the agent by the policy: a deny `fs.write` rule covers them
//!   (`openmoat_core::lint::write_denied`), or
//! - kept from every user but an administrator by the system: on Unix the
//!   file and every folder above it are owned by root and writable by no group
//!   or other user.
//!
//! Neither path may lie in a folder every user can write (`/tmp` and the like).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::{Policy, SecretCommand};

/// The resolved program file of `written` (absolute, home already expanded),
/// once it is a program the agent cannot change. `home` is the person's home
/// in slash form.
pub fn check(written: &str, policy: &Policy, home: &str) -> Result<PathBuf> {
    let real = std::fs::canonicalize(written)
        .with_context(|| format!("source command {written} cannot be found"))?;
    let meta = std::fs::metadata(&real).with_context(|| format!("reading {}", real.display()))?;
    ensure!(meta.is_file(), "source command {written} is not a file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            meta.permissions().mode() & 0o111 != 0,
            "source command {written} is not executable"
        );
    }
    let shown = slashed(&real);
    for path in [written.replace('\\', "/"), shown.clone()] {
        if let Some(dir) = SecretCommand::shared_temp_dir(&path) {
            bail!("source command {path} is under {dir}, where any user can put a file");
        }
    }
    // A rule may name a file under the home as `~/…` or by its full path.
    let by_policy = [written, shown.as_str()].iter().all(|p| {
        [policy_form(p, home), p.replace('\\', "/")]
            .iter()
            .any(|form| openmoat_core::lint::write_denied(policy, form))
    });
    if by_policy || (admin_only(Path::new(written)) && admin_only(&real)) {
        return Ok(real);
    }
    bail!(
        "source command {written} could be changed by the agent: add a deny rule with \
         `fs.write: [\"{}\"]` (and the folder it is installed in) to your policy, or use a \
         program only an administrator can change",
        policy_form(&shown, home)
    )
}

/// SHA-256 of the program file.
pub fn digest(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(crate::integrity::sha256_hex(&bytes))
}

/// `path` as policy rules name it: under the home as `~/…`.
fn policy_form(path: &str, home: &str) -> String {
    let path = path.replace('\\', "/");
    let home = home.trim_end_matches('/');
    match path.strip_prefix(home) {
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path,
    }
}

fn slashed(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    // `canonicalize` on Windows gives a `\\?\` path.
    text.strip_prefix("//?/")
        .map_or(text.clone(), str::to_owned)
}

/// Whether only an administrator can change `path`: it (a link is not
/// followed) and every folder above it belong to root and no group or other
/// user may write them.
#[cfg(unix)]
pub(super) fn admin_only(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    path.ancestors().all(|p| {
        p.as_os_str().is_empty()
            || std::fs::symlink_metadata(p).is_ok_and(|m| {
                m.uid() == 0 && (m.file_type().is_symlink() || m.mode() & 0o022 == 0)
            })
    })
}

/// No such check is made here: the policy must keep the program from the agent.
#[cfg(not(unix))]
pub(super) fn admin_only(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_under_the_home_are_written_as_policy_rules_name_them() {
        assert_eq!(
            policy_form("/Users/me/sdk/bin/x", "/Users/me"),
            "~/sdk/bin/x"
        );
        assert_eq!(policy_form("/Users/me2/x", "/Users/me"), "/Users/me2/x");
        assert_eq!(policy_form("/usr/bin/x", "/Users/me/"), "/usr/bin/x");
    }

    #[cfg(unix)]
    #[test]
    fn a_system_program_is_kept_by_the_system_and_a_users_file_is_not() {
        // `/bin/sh` and every folder above it belong to root on macOS and Linux.
        assert!(admin_only(Path::new("/bin/sh")));
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x");
        std::fs::write(&file, "").unwrap();
        assert!(!admin_only(&file));
    }
}

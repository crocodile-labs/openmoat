//! The commands a person runs to put a managed hook file in place, or take
//! it away, where that needs an administrator: OpenMoat prints them and never
//! runs them itself.

use std::path::Path;

use openmoat_hosts::Platform;

/// The command that installs `staged` at `target`, owned by root and
/// writable by no one else (GitHub Copilot CLI refuses a policy file that is
/// not), its folder created first; on Windows from an elevated PowerShell.
#[must_use]
pub fn install_command(staged: &Path, target: &Path, platform: Platform) -> String {
    let dir = target.parent().unwrap_or(target);
    match platform {
        Platform::Windows => format!(
            "in an elevated PowerShell: New-Item -ItemType Directory -Force -Path {} | Out-Null; \
             Copy-Item -Force -Path {} -Destination {}",
            powershell(dir),
            powershell(staged),
            powershell(target)
        ),
        Platform::MacOs | Platform::Linux | Platform::Wsl => format!(
            "sudo install -d -m 755 {} && sudo install -m 644 -o 0 -g 0 {} {}",
            posix(dir),
            posix(staged),
            posix(target)
        ),
    }
}

/// The command that removes `target`.
#[must_use]
pub fn remove_command(target: &Path, platform: Platform) -> String {
    match platform {
        Platform::Windows => format!(
            "in an elevated PowerShell: Remove-Item -Force -Path {}",
            powershell(target)
        ),
        Platform::MacOs | Platform::Linux | Platform::Wsl => {
            format!("sudo rm -f {}", posix(target))
        }
    }
}

/// `path` as one word of a POSIX shell: single-quoted, a quote in it closed,
/// escaped and opened again.
fn posix(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

/// `path` as one PowerShell word: single-quoted, a quote in it doubled.
fn powershell(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}

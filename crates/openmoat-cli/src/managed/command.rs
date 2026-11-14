//! The commands a person runs to put a managed hook file in place, or take
//! it away, where that needs an administrator: OpenMoat prints them and never
//! runs them itself. The install command checks the kept file's SHA-256
//! before it copies anything, and creates the folder only when it is
//! missing, leaving an existing folder's mode and access list as they are.

use std::path::Path;

use openmoat_hosts::Platform;

/// The command that installs `staged`, whose SHA-256 is `digest` (hex), at
/// `target`, owned by root and writable by no one else (GitHub Copilot CLI
/// refuses a policy file that is not); on Windows from an elevated
/// PowerShell.
#[must_use]
pub fn install_command(staged: &Path, digest: &str, target: &Path, platform: Platform) -> String {
    let dir = target.parent().unwrap_or(target);
    match platform {
        Platform::Windows => format!(
            "in an elevated PowerShell: if ((Get-FileHash -Algorithm SHA256 -LiteralPath {}).Hash \
             -ne '{}') {{ throw 'the kept file changed; run openmoat init --managed again' }}; \
             if (-not (Test-Path -LiteralPath {})) {{ New-Item -ItemType Directory -Path {} | \
             Out-Null }}; Copy-Item -Force -LiteralPath {} -Destination {}",
            powershell(staged),
            digest.to_ascii_uppercase(),
            powershell(dir),
            powershell(dir),
            powershell(staged),
            powershell(target)
        ),
        Platform::MacOs | Platform::Linux | Platform::Wsl => {
            let check = match platform {
                Platform::MacOs => "shasum -a 256 -c",
                _ => "sha256sum -c",
            };
            format!(
                "echo '{digest}  '{} | {check} - && {{ [ -d {} ] || sudo install -d -m 755 {}; }} \
                 && sudo install -m 644 -o 0 -g 0 {} {}",
                posix(staged),
                posix(dir),
                posix(dir),
                posix(staged),
                posix(target)
            )
        }
    }
}

/// The command that removes `target`.
#[must_use]
pub fn remove_command(target: &Path, platform: Platform) -> String {
    match platform {
        Platform::Windows => format!(
            "in an elevated PowerShell: Remove-Item -Force -LiteralPath {}",
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

//! Windows: the state directory's list through Win32 calls (`win32.rs`), no
//! program started (ADR-083). `icacls.exe`'s path is kept for the fix
//! `doctor` prints for a person to run.

use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

mod win32;

/// Where Windows is installed when `SystemRoot` does not say otherwise.
const DEFAULT_ROOT: &str = r"C:\Windows";

/// What a failure to set the list most likely means.
const NO_ACCESS_LISTS: &str =
    "the drive may not keep access lists (FAT or exFAT): put MOAT_HOME on an NTFS drive";

/// The `icacls.exe` in `<SystemRoot>\System32`, for the fix `doctor` prints.
/// `SystemRoot` is taken only when it is an absolute path.
pub fn icacls() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|root| root.is_absolute())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
    root.join(r"System32\icacls.exe")
}

/// `dir` as the NUL-terminated UTF-16 the Win32 calls take.
fn wide(dir: &Path) -> Result<Vec<u16>> {
    let mut units: Vec<u16> = dir.as_os_str().encode_wide().collect();
    if units.contains(&0) {
        bail!("{} holds a NUL character", dir.display());
    }
    units.push(0);
    Ok(units)
}

/// This account's SID and `dir`'s owner and DACL as SDDL with full SIDs.
pub fn read(dir: &Path) -> Result<(String, String)> {
    let me = win32::current_sid()?;
    let descriptor = win32::read(&wide(dir)?)
        .with_context(|| format!("reading the access list of {}", dir.display()))?;
    Ok((me, super::sddl_of(&descriptor)))
}

/// Give `dir` exactly two entries, full control for this account and
/// `SYSTEM`, with inheritance off (ADR-083), and check that it holds. A
/// folder that `existed` before is read first and refused when another
/// account owns it. One `SetNamedSecurityInfoW` replaces the whole list, so
/// an explicit entry for any other account (Administrators, on a folder an
/// administrator made) goes too; the list is then read back, and anything
/// but the two entries is an error, so a list that could not be set never
/// passes as set.
pub fn protect(dir: &Path, existed: bool) -> Result<()> {
    let me = win32::current_sid()?;
    let path = wide(dir)?;
    if existed {
        let sddl = super::sddl_of(
            &win32::read(&path)
                .with_context(|| format!("reading the access list of {}", dir.display()))?,
        );
        if let Some(owner) = super::judge(&sddl, &me).foreign_owner {
            bail!(
                "the state directory {} is owned by {owner}, not by you; OpenMoat does not take \
                 it over: move it away, or set MOAT_HOME to a folder of your own",
                dir.display()
            );
        }
    }
    win32::set_two(&path, &me).with_context(|| {
        format!(
            "setting the access list of {}; {NO_ACCESS_LISTS}",
            dir.display()
        )
    })?;
    let after = super::sddl_of(
        &win32::read(&path)
            .with_context(|| format!("reading the access list of {}", dir.display()))?,
    );
    if let Err(stayed) = super::verify(&after, &me) {
        bail!(
            "the access list of {} still holds more than your account and SYSTEM after \
             `openmoat init` set it: {stayed}",
            dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After `protect` the list holds only this account and `SYSTEM`, a file
    /// that was there before gets it too, and an entry for another account
    /// added by hand is taken out by the next `protect`.
    #[test]
    fn protect_leaves_only_this_account_and_system() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let before = state.join("policy.lock");
        std::fs::write(&before, "x").unwrap();
        protect(&state, false).unwrap();
        let (me, sddl) = read(&state).unwrap();
        assert_eq!(super::super::verify(&sddl, &me), Ok(()), "{sddl}");

        let widened = std::process::Command::new(icacls())
            .arg(&state)
            .args(["/grant", "*S-1-1-0:(OI)(CI)M", "/q"])
            .status()
            .unwrap();
        assert!(widened.success());
        let (_, wide) = read(&state).unwrap();
        assert_eq!(
            super::super::judge(&wide, &me).writers,
            ["Everyone"],
            "{wide}"
        );
        protect(&state, true).unwrap();
        let (_, sddl) = read(&state).unwrap();
        assert_eq!(super::super::verify(&sddl, &me), Ok(()), "{sddl}");
        // OpenMoat itself still writes there
        std::fs::write(state.join("audit.db"), "y").unwrap();
        std::fs::write(&before, "z").unwrap();
    }
}

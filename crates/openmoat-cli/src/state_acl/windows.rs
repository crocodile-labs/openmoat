//! Windows: run `whoami.exe`, `icacls.exe` and Windows PowerShell from the
//! system folder by absolute path, never from the search path, where a
//! planted copy would be found first.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

/// Where Windows is installed when `SystemRoot` does not say otherwise.
const DEFAULT_ROOT: &str = r"C:\Windows";

/// What a failure to set the list most likely means.
const NO_ACCESS_LISTS: &str =
    "the drive may not keep access lists (FAT or exFAT): put MOAT_HOME on an NTFS drive";

/// The variable the PowerShell read takes the folder from, so the path is
/// never part of the script's text.
const DIR_VARIABLE: &str = "OPENMOAT_ACL_DIR";

/// This account's SID, then the folder's owner and DACL in SDDL with every
/// SID in full, one per line. SDDL itself writes some accounts as aliases,
/// machine-relative ones too (the built-in Administrator, RID 500, is `LA`),
/// so the script rebuilds the string from .NET's `RawSecurityDescriptor`:
/// the owner's and each entry's `SecurityIdentifier.Value`, the entry's
/// type, flags (`OI`, `CI`, `NP`, `IO`, `ID`) and access mask in hex, and `P`
/// when inheritance is off. Then no alias has to be read to compare an
/// account with this one. An entry of a kind without these fields stops the
/// script, which is an error. `System.IO.Directory.GetAccessControl` is .NET
/// Framework's, which Windows PowerShell runs on; no module has to load.
const READ_SCRIPT: &str = "$ErrorActionPreference = 'Stop'; \
     [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
     $sddl = [IO.Directory]::GetAccessControl($env:OPENMOAT_ACL_DIR).GetSecurityDescriptorSddlForm('Owner, Access'); \
     $sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl; \
     $out = 'O:' + $sd.Owner.Value + 'D:'; \
     if ($null -eq $sd.DiscretionaryAcl) { $out += 'NO_ACCESS_CONTROL' } else { \
       if (([int]$sd.ControlFlags -band 0x1000) -ne 0) { $out += 'P' }; \
       foreach ($ace in $sd.DiscretionaryAcl) { \
         $kind = 'A'; \
         if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessDenied) { $kind = 'D' }; \
         $f = [int]$ace.AceFlags; $flags = ''; \
         if ($f -band 1) { $flags += 'OI' }; if ($f -band 2) { $flags += 'CI' }; \
         if ($f -band 4) { $flags += 'NP' }; if ($f -band 8) { $flags += 'IO' }; \
         if ($f -band 16) { $flags += 'ID' }; \
         $out += '(' + $kind + ';' + $flags + ';0x' + $ace.AccessMask.ToString('x') + ';;;' + $ace.SecurityIdentifier.Value + ')' \
       } \
     }; \
     $out";

/// `<SystemRoot>\<relative>`. `SystemRoot` is taken only when it is an
/// absolute path.
fn system_program(relative: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|root| root.is_absolute())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
    root.join(relative)
}

/// The `icacls.exe` OpenMoat runs, for the fix `doctor` prints too.
pub fn icacls() -> PathBuf {
    system_program(r"System32\icacls.exe")
}

/// Run `program` with `args` (and `env`) and return what it printed, or why
/// it failed.
fn run(program: &Path, args: &[OsString], env: Option<(&str, &OsStr)>) -> Result<String> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    if let Some((name, value)) = env {
        command.env(name, value);
    }
    let out = command
        .output()
        .with_context(|| format!("running {}", program.display()))?;
    if !out.status.success() {
        bail!(
            "{} failed: {}{}",
            program.display(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The SID of the account this process runs as.
fn current_sid() -> Result<String> {
    let args = ["/user", "/fo", "csv", "/nh"].map(OsString::from);
    let printed = run(&system_program(r"System32\whoami.exe"), &args, None)?;
    super::parse_sid(&printed).with_context(|| format!("no SID in whoami's answer: {printed}"))
}

/// This account's SID and `dir`'s owner and DACL in SDDL.
pub fn read(dir: &Path) -> Result<(String, String)> {
    let powershell = system_program(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let args = [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        READ_SCRIPT,
    ]
    .map(OsString::from);
    let printed = run(&powershell, &args, Some((DIR_VARIABLE, dir.as_os_str())))
        .with_context(|| format!("reading the access list of {}", dir.display()))?;
    super::parse_read(&printed).with_context(|| {
        format!(
            "no SID and access list in what PowerShell printed for {}: {printed}",
            dir.display()
        )
    })
}

/// Give `dir` exactly two entries, full control for this account and
/// `SYSTEM` (ADR-083), and check that it holds. A folder that `existed`
/// before is read first and refused when another account owns it. Then
/// `/inheritance:r /grant:r` sets the two entries, the list is read back
/// (explicit entries survive `/inheritance:r`: the Administrators group's,
/// on a folder an administrator made), every other entry is removed, and
/// the result is read again: anything but the two entries is an error, so a
/// list `protect` could not set never passes as set.
pub fn protect(dir: &Path, existed: bool) -> Result<()> {
    let me = if existed {
        let (me, sddl) = read(dir)?;
        if let Some(owner) = super::judge(&sddl, &me).foreign_owner {
            bail!(
                "the state directory {} is owned by {owner}, not by you; OpenMoat does not take \
                 it over: move it away, or set MOAT_HOME to a folder of your own",
                dir.display()
            );
        }
        me
    } else {
        current_sid()?
    };
    let icacls = icacls();
    let dir_os = dir.as_os_str();
    set(&icacls, dir, &super::grant_args(dir_os, &me))?;
    let (_, granted) = read(dir)?;
    let plan = match super::plan(&granted, &me) {
        Ok(plan) => plan,
        Err(alias) => bail!(
            "the access list of {} names `{alias}`, an account OpenMoat cannot name to icacls: \
             remove that entry, then run `openmoat init` again",
            dir.display()
        ),
    };
    let removals = plan
        .remove
        .iter()
        .map(|sid| super::remove_args(dir_os, sid, false))
        .chain(
            plan.remove_denies
                .iter()
                .map(|sid| super::remove_args(dir_os, sid, true)),
        )
        .collect::<Vec<_>>();
    for args in &removals {
        set(&icacls, dir, args)?;
    }
    // nothing removed: the list read after the grant is the one to check
    let after = if removals.is_empty() {
        granted
    } else {
        read(dir)?.1
    };
    if let Err(stayed) = super::verify(&after, &me) {
        bail!(
            "the access list of {} still holds more than your account and SYSTEM after \
             `openmoat init` set it: {stayed}",
            dir.display()
        );
    }
    Ok(())
}

/// One `icacls` call that changes `dir`'s list.
fn set(icacls: &Path, dir: &Path, args: &[OsString]) -> Result<()> {
    run(icacls, args, None).with_context(|| {
        format!(
            "setting the access list of {}; {NO_ACCESS_LISTS}",
            dir.display()
        )
    })?;
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

        let everyone = ["/grant", "*S-1-1-0:(OI)(CI)M", "/q"].map(OsString::from);
        let mut widen = vec![state.as_os_str().to_owned()];
        widen.extend(everyone);
        run(&icacls(), &widen, None).unwrap();
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

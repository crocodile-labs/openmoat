//! The access list of OpenMoat's state directory on Windows (ADR-083): what
//! `openmoat init` sets and `openmoat doctor` reads back.
//!
//! On Unix the directory is `0700`. On Windows `init` gives it exactly two
//! entries, full control for the person's account and for `SYSTEM`, both
//! handed on to everything inside: `icacls <dir> /inheritance:r /grant:r …`
//! drops the inherited entries and sets those two, then `icacls <dir> /remove
//! *<sid>` takes out every other account an explicit entry names
//! (<https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls>).
//! The owner of a folder may change its list without being an administrator.
//! `init` refuses a directory another account owns. Programs run from
//! `%SystemRoot%\System32` by absolute path: the crate forbids `unsafe`, and
//! every Win32 security call is foreign code.
//!
//! The list keeps other accounts out (a second user, a sandbox's own account,
//! `Authenticated Users` on a drive whose root grants them a change). It does
//! not keep the agent out: the agent runs as the person, and an account may
//! always change the list of a folder it owns. That is the hook's
//! `kernel-self` rule's job, and a sandbox's.
//!
//! This file reads the owner and DACL in SDDL (`O:…D:P(A;OICI;FA;;;SY)…`) and
//! plans the `icacls` calls, on every system, so its tests run everywhere; the
//! programs run only on Windows (`state_acl/windows.rs`).

use std::ffi::{OsStr, OsString};
use std::path::Path;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{icacls, protect, read};

/// `SYSTEM`'s SID, in SDDL and as `icacls` takes it.
pub const SYSTEM: &str = "S-1-5-18";

/// Access rights that change a file or folder, its contents, its access list
/// or its owner: write data / add file, append / add folder, write extended
/// attributes, delete a child, write attributes, delete, write DAC, write
/// owner, generic write, generic all.
const WRITE_MASK: u32 =
    0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000;
/// Access rights that read a file's data or list a folder: read data / list,
/// generic read, generic all.
const READ_MASK: u32 = 0x1 | 0x8000_0000 | 0x1000_0000;

/// SDDL's aliases for well-known accounts, with their SIDs (`icacls` takes a
/// SID, not an alias).
const ALIASES: &[(&str, &str)] = &[
    ("SY", SYSTEM),
    ("BA", "S-1-5-32-544"),
    ("BU", "S-1-5-32-545"),
    ("BG", "S-1-5-32-546"),
    ("PU", "S-1-5-32-547"),
    ("WD", "S-1-1-0"),
    ("AU", "S-1-5-11"),
    ("IU", "S-1-5-4"),
    ("NU", "S-1-5-2"),
    ("AN", "S-1-5-7"),
    ("RC", "S-1-5-12"),
    ("LS", "S-1-5-19"),
    ("NS", "S-1-5-20"),
    ("CO", "S-1-3-0"),
    ("CG", "S-1-3-1"),
    ("OW", "S-1-3-4"),
    ("AC", "S-1-15-2-1"),
];

/// What the state directory's owner and DACL allow, as [`judge`] reads them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Judged {
    /// Inheritance is off (`D:P…`): the folder above cannot widen it.
    pub protected: bool,
    /// The owner, when it is another account than the person, `SYSTEM` or
    /// the administrators; it may change the list at any time.
    pub foreign_owner: Option<String>,
    /// Accounts other than the person, `SYSTEM` and the administrators that
    /// may change it or what is created inside, by name where SDDL has one.
    pub writers: Vec<String>,
    /// Accounts other than those that may read it without changing it.
    pub readers: Vec<String>,
}

/// The `icacls /remove` calls that leave only the person and `SYSTEM`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    /// SIDs every entry of which goes (`/remove`).
    pub remove: Vec<String>,
    /// The person's or `SYSTEM`'s SID whose deny entries go (`/remove:d`).
    pub remove_denies: Vec<String>,
}

/// The SID in `whoami /user /fo csv /nh`'s line (`"pc\me","S-1-5-21-…"`).
pub fn parse_sid(whoami: &str) -> Option<String> {
    let line = whoami.lines().find(|l| !l.trim().is_empty())?;
    let sid = line.rsplit(',').next()?.trim().trim_matches('"');
    is_sid(sid).then(|| sid.to_owned())
}

/// The account's SID and the folder's SDDL, as the PowerShell read in
/// `state_acl/windows.rs` prints them, one per line.
pub fn parse_read(printed: &str) -> Option<(String, String)> {
    let mut lines = printed.lines().map(str::trim).filter(|l| !l.is_empty());
    let me = lines.next().filter(|l| is_sid(l))?;
    let sddl = lines
        .next()
        .filter(|l| l.starts_with("O:") || l.starts_with("D:"))?;
    Some((me.to_owned(), sddl.to_owned()))
}

/// `S-1-` followed by numbers and dashes.
fn is_sid(text: &str) -> bool {
    text.strip_prefix("S-1-").is_some_and(|rest| {
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    })
}

/// The `icacls` arguments that give `dir` its two entries: inheritance off,
/// full control for `me` and `SYSTEM`, handed on to every file and folder
/// created inside.
pub fn grant_args(dir: &OsStr, me: &str) -> Vec<OsString> {
    let mut args = vec![dir.to_owned()];
    args.extend(
        [
            "/inheritance:r".to_owned(),
            "/grant:r".to_owned(),
            format!("*{me}:(OI)(CI)F"),
            format!("*{SYSTEM}:(OI)(CI)F"),
            "/q".to_owned(),
        ]
        .map(OsString::from),
    );
    args
}

/// The `icacls` arguments that take every entry naming `sid` off `dir`, or
/// only its deny entries.
pub fn remove_args(dir: &OsStr, sid: &str, denies_only: bool) -> Vec<OsString> {
    let remove = if denies_only { "/remove:d" } else { "/remove" };
    vec![
        dir.to_owned(),
        remove.into(),
        format!("*{sid}").into(),
        "/q".into(),
    ]
}

/// Every `icacls` call [`grant_args`] and `plan` make, as one would type them.
pub fn fix_commands(icacls: &Path, dir: &Path, me: &str, plan: &Plan) -> Vec<String> {
    let dir = dir.as_os_str();
    let removals = plan
        .remove
        .iter()
        .map(|sid| remove_args(dir, sid, false))
        .chain(
            plan.remove_denies
                .iter()
                .map(|sid| remove_args(dir, sid, true)),
        );
    std::iter::once(grant_args(dir, me))
        .chain(removals)
        .map(|args| {
            std::iter::once(icacls.as_os_str().to_owned())
                .chain(args)
                .map(|a| quoted(&a.to_string_lossy()))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// `text`, in double quotes when a shell would split or read it.
fn quoted(text: &str) -> String {
    if text.contains([' ', '(', ')']) {
        format!("\"{text}\"")
    } else {
        text.to_owned()
    }
}

/// The owner field of `sddl` (`O:S-1-5-21-…`), when it has one.
fn owner(sddl: &str) -> Option<&str> {
    let rest = sddl.strip_prefix("O:")?;
    let end = ["G:", "D:", "S:"]
        .iter()
        .filter_map(|tag| rest.find(tag))
        .min()
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The DACL of `sddl` (`D:…`), when it has one that is not null.
fn dacl(sddl: &str) -> Option<&str> {
    let at = sddl.find("D:")?;
    let dacl = &sddl[at + 2..];
    let dacl = &dacl[..dacl.find("S:").unwrap_or(dacl.len())];
    (!dacl.starts_with("NO_ACCESS_CONTROL")).then_some(dacl)
}

/// Each ACE of a DACL: whether it allows, its flags, rights and SID.
fn aces(dacl: &str) -> impl Iterator<Item = (bool, &str, &str, &str)> {
    dacl.split('(').skip(1).filter_map(|ace| {
        let fields: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
        let [kind, flags, rights, _, _, sid, ..] = fields.as_slice() else {
            return None;
        };
        Some((
            matches!(*kind, "A" | "OA" | "XA" | "ZA"),
            *flags,
            *rights,
            *sid,
        ))
    })
}

/// Read the owner and DACL in `sddl` for `me` (the person's SID). Deny entries
/// only narrow and are left out; an entry that passes only to what is created
/// inside (`IO`) counts, since the state files are created there. A right
/// SDDL spells in a way not read here counts as able to change and read.
pub fn judge(sddl: &str, me: &str) -> Judged {
    let foreign_owner = match owner(sddl) {
        Some(owner) if trusted(owner, me) => None,
        Some(owner) => Some(name_of(owner)),
        None => Some("an account that could not be read".to_owned()),
    };
    // no DACL, or a null one, lets everyone do everything
    let Some(dacl) = dacl(sddl) else {
        return Judged {
            foreign_owner,
            writers: vec!["everyone (no access list)".to_owned()],
            ..Judged::default()
        };
    };
    let flags = &dacl[..dacl.find('(').unwrap_or(dacl.len())];
    let mut judged = Judged {
        protected: flags.contains('P'),
        foreign_owner,
        ..Judged::default()
    };
    for (allows, _, rights, sid) in aces(dacl) {
        if !allows || trusted(sid, me) || matches!(sid, "CO" | "OW") {
            continue;
        }
        let mask = rights_mask(rights);
        let name = name_of(sid);
        if mask & WRITE_MASK != 0 {
            judged.writers.push(name);
        } else if mask & READ_MASK != 0 {
            judged.readers.push(name);
        }
    }
    judged
}

/// The removals after which only `me` and `SYSTEM` remain in `sddl`'s DACL,
/// once `/inheritance:r` has dropped the inherited entries (`ID`); an SDDL
/// alias whose SID is not known here is the error.
pub fn plan(sddl: &str, me: &str) -> Result<Plan, String> {
    let mut plan = Plan::default();
    for (allows, flags, _, sid) in dacl(sddl).into_iter().flat_map(aces) {
        if flags.as_bytes().chunks(2).any(|flag| flag == b"ID") {
            continue;
        }
        let sid = sid_of(sid).ok_or_else(|| sid.to_owned())?;
        let own = sid.eq_ignore_ascii_case(me) || sid == SYSTEM;
        let list = match (own, allows) {
            (true, true) => continue,
            (true, false) => &mut plan.remove_denies,
            (false, _) => &mut plan.remove,
        };
        if !list.contains(&sid) {
            list.push(sid);
        }
    }
    Ok(plan)
}

/// A SID, or the SID of an SDDL alias.
fn sid_of(sid: &str) -> Option<String> {
    if is_sid(sid) {
        return Some(sid.to_owned());
    }
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == sid)
        .map(|(_, full)| (*full).to_owned())
}

/// The person, `SYSTEM`, and the administrators, whose group counts only in
/// an elevated process, which can take ownership of the folder anyway.
fn trusted(sid: &str, me: &str) -> bool {
    sid.eq_ignore_ascii_case(me) || matches!(sid, "SY" | "BA" | SYSTEM | "S-1-5-32-544")
}

/// A name for the SDDL aliases a profile's folders commonly carry.
fn name_of(sid: &str) -> String {
    match sid {
        "WD" => "Everyone",
        "AU" => "Authenticated Users",
        "BU" => "Users",
        "IU" => "interactive users",
        "AN" => "anonymous logons",
        "AC" => "all app containers",
        other => other,
    }
    .to_owned()
}

/// The access mask of an SDDL rights field: hexadecimal (`0x1301bf`) or
/// two-letter codes (`FA`, `GRGW`). An unknown code counts as every right.
fn rights_mask(rights: &str) -> u32 {
    if let Some(hex) = rights
        .strip_prefix("0x")
        .or_else(|| rights.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).unwrap_or(u32::MAX);
    }
    rights
        .as_bytes()
        .chunks(2)
        .map(|code| match code {
            b"GA" => 0x1000_0000,
            b"GR" => 0x8000_0000,
            b"GW" => 0x4000_0000,
            b"GX" => 0x2000_0000,
            b"FA" => 0x001F_01FF,
            b"FR" => 0x0012_0089,
            b"FW" => 0x0012_0116,
            b"FX" => 0x0012_00A0,
            b"RC" => 0x2_0000,
            b"SD" => 0x1_0000,
            b"WD" => 0x4_0000,
            b"WO" => 0x8_0000,
            b"CC" => 0x1,
            b"DC" => 0x2,
            b"LC" => 0x4,
            b"SW" => 0x8,
            b"RP" => 0x10,
            b"WP" => 0x20,
            b"DT" => 0x40,
            b"LO" => 0x80,
            b"CR" => 0x100,
            _ => u32::MAX,
        })
        .fold(0, |mask, bits| mask | bits)
}

#[cfg(test)]
mod tests;

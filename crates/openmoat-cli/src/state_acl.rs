//! The access list of OpenMoat's state directory on Windows (ADR-083): what
//! `openmoat init` sets and `openmoat doctor` reads back.
//!
//! On Unix the directory is `0700`. On Windows `init` gives it exactly two
//! entries, full control for the person's account and for `SYSTEM`, both
//! handed on to everything inside, with inheritance off: one
//! `SetNamedSecurityInfoW` call with a new DACL of those two entries and
//! `PROTECTED_DACL_SECURITY_INFORMATION`, which replaces whatever the list
//! held (an explicit Administrators entry on a folder an administrator made
//! included). The owner of a folder may change its list without being an
//! administrator. `init` refuses a directory another account owns, reads the
//! list back and refuses one that holds anything else. No program runs:
//! starting `icacls`, `whoami` or PowerShell for each `init` cost seconds on
//! every call, and the Win32 calls (`state_acl/windows/win32.rs`, the one
//! file of this code with `unsafe`) read and write the same data.
//!
//! The list keeps other accounts out (a second user, a sandbox's own account,
//! `Authenticated Users` on a drive whose root grants them a change). It does
//! not keep the agent out: the agent runs as the person, and an account may
//! always change the list of a folder it owns. That is the hook's
//! `kernel-self` rule's job, and a sandbox's.
//!
//! This file reads the owner and DACL as SDDL with every SID in full
//! (`O:S-1-5-21-…D:P(A;OICI;0x1f01ff;;;S-1-5-18)…`, [`sddl_of`] builds it from
//! what Windows returns; an SDDL alias such as `LA`, the built-in
//! Administrator, is resolved against the person's SID), judges and checks
//! it, and plans the `icacls` calls `doctor` prints as a person's fix, on
//! every system, so its tests run everywhere.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::Path;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{icacls, protect, read};

/// One entry of a DACL as Windows returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAce {
    /// An allow entry; otherwise a deny entry.
    pub allows: bool,
    /// The ACE flags: object inherit 1, container inherit 2, no propagate 4,
    /// inherit only 8, inherited 16.
    pub flags: u8,
    /// The access mask.
    pub mask: u32,
    /// The account, as a full SID (`S-1-5-18`).
    pub sid: String,
}

/// A folder's owner and DACL as Windows returns them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The owner, as a full SID.
    pub owner: String,
    /// Inheritance is off (`SE_DACL_PROTECTED`).
    pub protected: bool,
    /// The entries; `None` for a null DACL, which lets everyone in.
    pub aces: Option<Vec<RawAce>>,
}

/// `descriptor` as SDDL, every SID in full, for [`judge`], [`plan`] and
/// [`verify`].
pub fn sddl_of(descriptor: &Descriptor) -> String {
    let mut sddl = format!("O:{}D:", descriptor.owner);
    let Some(aces) = &descriptor.aces else {
        sddl.push_str("NO_ACCESS_CONTROL");
        return sddl;
    };
    if descriptor.protected {
        sddl.push('P');
    }
    for ace in aces {
        let kind = if ace.allows { "A" } else { "D" };
        let flags: String = [(1, "OI"), (2, "CI"), (4, "NP"), (8, "IO"), (16, "ID")]
            .iter()
            .filter(|(bit, _)| ace.flags & bit != 0)
            .map(|(_, name)| *name)
            .collect();
        let _ = write!(sddl, "({kind};{flags};0x{:x};;;{})", ace.mask, ace.sid);
    }
    sddl
}

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

/// The Administrators group, trusted as an owner only.
const ADMINISTRATORS: &str = "S-1-5-32-544";

/// `CREATOR OWNER` and `OWNER RIGHTS`, which stand for the owner.
const OWNER_STANDINS: &[&str] = &["S-1-3-0", "S-1-3-4"];

/// SDDL's machine-relative aliases, by the RID of the account they name:
/// the built-in Administrator (`LA`) and Guest (`LG`). SDDL writes these
/// accounts' SIDs this way, so the person's own account may appear as `LA`.
const LOCAL_ACCOUNTS: &[(&str, &str)] = &[("LA", "500"), ("LG", "501")];

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
    /// the Administrators group (which counts only in an elevated process,
    /// which can take ownership anyway); it may change the list at any time.
    pub foreign_owner: Option<String>,
    /// Accounts other than the person and `SYSTEM` that may change it or what
    /// is created inside, by name where one is known.
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
/// SDDL spells in a way not read here counts as able to change and read. Every
/// SID is compared in full ([`sid_of`]), so the person's own account written
/// as `LA` is the person.
pub fn judge(sddl: &str, me: &str) -> Judged {
    let foreign_owner = match owner(sddl) {
        Some(owner) if sid_of(owner, me).is_some_and(|sid| owner_trusted(&sid, me)) => None,
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
        let full = sid_of(sid, me);
        let own = full
            .as_deref()
            .is_some_and(|f| is_own(f, me) || OWNER_STANDINS.contains(&f));
        if !allows || own {
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
        let sid = sid_of(sid, me).ok_or_else(|| sid.to_owned())?;
        let list = match (is_own(&sid, me), allows) {
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

/// Whether `sddl` is the list `protect` sets: inheritance off, only `me` and
/// `SYSTEM` in it, owned by one of them or the Administrators group; or what
/// stayed, as the error.
pub fn verify(sddl: &str, me: &str) -> Result<(), String> {
    let judged = judge(sddl, me);
    let mut stayed: Vec<String> = Vec::new();
    if let Some(owner) = &judged.foreign_owner {
        stayed.push(format!("the owner {owner}"));
    }
    if !judged.protected {
        stayed.push("entries inherited from the folder above".to_owned());
    }
    stayed.extend(
        judged
            .writers
            .iter()
            .map(|w| format!("{w}, who may change it")),
    );
    stayed.extend(
        judged
            .readers
            .iter()
            .map(|r| format!("{r}, who may read it")),
    );
    match plan(sddl, me) {
        Ok(plan) => {
            stayed.extend(plan.remove.iter().map(|sid| format!("an entry for {sid}")));
            stayed.extend(
                plan.remove_denies
                    .iter()
                    .map(|sid| format!("a deny entry for {sid}")),
            );
        }
        Err(alias) => stayed.push(format!("an entry for `{alias}`")),
    }
    stayed.dedup();
    if stayed.is_empty() {
        Ok(())
    } else {
        Err(stayed.join("; "))
    }
}

/// The full SID `sid` stands for: a SID as it is, an SDDL alias of a
/// well-known account, or a machine-relative alias (`LA`, `LG`): `me` when
/// `me` has that RID, otherwise the account of that RID beside `me` when
/// `me` is a local account. `None` for an alias not known here. A
/// machine-relative alias read against a domain account may name the wrong
/// account; `protect` reads the list again after its changes and refuses
/// what stayed, so that fails closed.
fn sid_of(sid: &str, me: &str) -> Option<String> {
    if is_sid(sid) {
        return Some(sid.to_owned());
    }
    if let Some((_, rid)) = LOCAL_ACCOUNTS.iter().find(|(alias, _)| *alias == sid) {
        let (domain, own_rid) = me.rsplit_once('-')?;
        if own_rid == *rid {
            return Some(me.to_owned());
        }
        return me
            .starts_with("S-1-5-21-")
            .then(|| format!("{domain}-{rid}"));
    }
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == sid)
        .map(|(_, full)| (*full).to_owned())
}

/// The person or `SYSTEM`: the only entries the list should hold.
fn is_own(sid: &str, me: &str) -> bool {
    sid.eq_ignore_ascii_case(me) || sid == SYSTEM
}

/// An owner that is the person, `SYSTEM` or the Administrators group, whose
/// rights count only in an elevated process, which can take ownership of the
/// folder anyway.
fn owner_trusted(sid: &str, me: &str) -> bool {
    is_own(sid, me) || sid == ADMINISTRATORS
}

/// A name for the accounts a profile's folders commonly carry, by SDDL alias
/// or SID.
fn name_of(sid: &str) -> String {
    match sid {
        "WD" | "S-1-1-0" => "Everyone",
        "AU" | "S-1-5-11" => "Authenticated Users",
        "BU" | "S-1-5-32-545" => "Users",
        "BA" | ADMINISTRATORS => "Administrators",
        "IU" | "S-1-5-4" => "interactive users",
        "AN" | "S-1-5-7" => "anonymous logons",
        "AC" | "S-1-15-2-1" => "all app containers",
        "LA" => "the built-in Administrator",
        "LG" => "the built-in Guest",
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

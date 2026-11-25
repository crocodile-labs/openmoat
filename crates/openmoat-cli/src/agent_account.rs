//! OpenMoat's agent account on Windows (ADR-129): what `openmoat
//! agent-account setup` makes, records and checks, and what `openmoat run`
//! changes per run. Pure: this file decides and compares; the Win32 calls are
//! in `commands/run/windows/account/`, so these tests run on every system.
//!
//! The account is a local user `openmoat-<person>` in no local group, so it
//! holds only what `Authenticated Users`, `Everyone` and entries naming it
//! grant. Setup grants it read and run on the person's profile (one inherited
//! entry), and `openmoat run` grants it write on the run's write roots and
//! denies it the places the policy's read denies name. The state directory
//! needs no entry: its list is protected and names the person and `SYSTEM`
//! only (ADR-083), so the profile's entry never reaches it.
//!
//! The record, `agent-account.json` in the state directory, names everything
//! setup and the runs changed, so `remove` undoes exactly that and `status`
//! can compare it with the system.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The record's file in the state directory.
pub const RECORD_FILE: &str = "agent-account.json";

/// The folder of the state directory that holds the account's password,
/// encrypted for the person with DPAPI.
pub const DIR: &str = "agent-account";

/// The encrypted password's file in [`DIR`].
pub const PASSWORD_FILE: &str = "password.dpapi";

/// The record's format.
pub const VERSION: u32 = 1;

/// Every agent account's name starts with this.
pub const PREFIX: &str = "openmoat-";

/// Windows' limit on a local account's name: "User account names are limited
/// to 20 characters" (`USER_INFO_1`, `NetUserAdd`).
const MAX_NAME: usize = 20;

/// Characters a local account's name may not hold (Microsoft's "User name
/// restrictions"), and the space, which no tool quotes reliably.
const FORBIDDEN: &[char] = &[
    '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@', ' ', '%',
];

/// The one logon right the account holds: the Secondary Logon service starts
/// `CreateProcessWithLogonW`'s process with an interactive logon.
pub const INTERACTIVE_RIGHT: &str = "SeInteractiveLogonRight";

/// The logon rights the account is denied: from the network, over remote
/// desktop, as a service and as a batch job.
pub const DENIED_RIGHTS: [&str; 4] = [
    "SeDenyNetworkLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
    "SeDenyServiceLogonRight",
    "SeDenyBatchLogonRight",
];

/// What the account may do on the person's profile: `FILE_GENERIC_READ |
/// FILE_GENERIC_EXECUTE`, read and run, nothing else.
pub const PROFILE_MASK: u32 = 0x0012_00A9;

/// What a read deny takes from the account on a place: `FILE_ALL_ACCESS`.
pub const READ_DENY_MASK: u32 = 0x001F_01FF;

/// Where Windows reads which accounts the sign-in screen leaves out: a
/// `DWORD` value 0 named after the account (HKLM).
pub const USER_LIST_KEY: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

/// Where setup registers the account's SID for the hook relay (HKLM): only an
/// administrator can write there, so a hook that finds its own SID there is
/// one an administrator set up as an agent account.
pub const RELAY_KEY: &str = r"SOFTWARE\OpenMoat\AgentAccounts";

/// `CreateProcessWithLogonW`'s limit on `lpCommandLine`: "The maximum length
/// of this string is 1024 characters."
pub const COMMAND_LINE_MAX: usize = 1024;

/// How the refusals of an unelevated setup or remove end.
pub const ELEVATE: &str = "run it from an administrator terminal (Terminal or PowerShell, \"Run \
                           as administrator\")";

/// One access-list entry that names the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclEntry {
    /// The file or folder, slash-separated.
    pub path: String,
    /// An allow entry; otherwise a deny entry.
    pub allows: bool,
    pub mask: u32,
    /// Handed to everything below.
    pub inherit: bool,
}

impl AclEntry {
    fn same(&self, other: &Self) -> bool {
        self.path.eq_ignore_ascii_case(&other.path)
            && self.allows == other.allows
            && self.mask == other.mask
            && self.inherit == other.inherit
    }
}

/// The network filters of ADR-129's second step. Not set up by this version:
/// the record says `"wfp": null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wfp {
    /// The provider's key.
    pub provider: String,
    /// The filters' keys.
    pub filters: Vec<String>,
    /// The first and last port of the range the runs' proxies listen on.
    pub ports: [u16; 2],
}

/// `agent-account.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub version: u32,
    /// The account's name.
    pub account: String,
    /// The account's SID.
    pub sid: String,
    /// The SID of the person who set it up.
    pub person_sid: String,
    /// The person's profile folder, slash-separated.
    pub profile: String,
    /// The logon rights it holds.
    pub rights: Vec<String>,
    /// The logon rights it is denied.
    pub denied_rights: Vec<String>,
    /// Its value in [`USER_LIST_KEY`] was set.
    pub hidden: bool,
    /// Its SID was registered in [`RELAY_KEY`].
    pub relay_registered: bool,
    /// The read entry on the profile.
    pub profile_entry: AclEntry,
    /// The network filters; `None` until ADR-129's second step.
    pub wfp: Option<Wfp>,
    /// The write entries runs set (kept between runs, like ADR-115's).
    #[serde(default)]
    pub write_entries: Vec<AclEntry>,
    /// The read denies the last run set (reconciled by each run).
    #[serde(default)]
    pub read_entries: Vec<AclEntry>,
}

impl Record {
    /// A record read from `text`, refused when its version, name or SID are
    /// not the ones setup writes.
    pub fn parse(text: &str) -> Result<Self> {
        let record: Self =
            serde_json::from_str(text).context("reading the agent account's record")?;
        if record.version != VERSION {
            bail!(
                "the agent account's record has version {}, this OpenMoat reads {VERSION}",
                record.version
            );
        }
        if !record.account.starts_with(PREFIX) || record.account.len() > MAX_NAME {
            bail!(
                "the agent account's record names `{}`, not an account setup makes",
                record.account
            );
        }
        if !record.sid.starts_with("S-1-5-21-") {
            bail!(
                "the agent account's record names the SID {}, not a local account's",
                record.sid
            );
        }
        Ok(record)
    }

    /// The record in `dir` (the state directory); `None` when there is none.
    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(RECORD_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text)
                .with_context(|| format!("in {}", path.display()))
                .map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// The record as setup writes it.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }

    /// Every entry naming the account that `remove` takes out: the profile's,
    /// then the runs'.
    pub fn entries(&self) -> impl Iterator<Item = &AclEntry> {
        std::iter::once(&self.profile_entry)
            .chain(&self.write_entries)
            .chain(&self.read_entries)
    }

    /// Add `entries` to the write entries the record names, once each.
    pub fn add_writes(&mut self, entries: &[AclEntry]) {
        for entry in entries {
            if !self.write_entries.iter().any(|e| e.same(entry)) {
                self.write_entries.push(entry.clone());
            }
        }
    }
}

/// The read denies of an earlier run that this one does not set: what a run
/// takes out first, so a run for another agent does not inherit the last
/// one's (ADR-129 §2, "Reads").
pub fn stale(previous: &[AclEntry], wanted: &[AclEntry]) -> Vec<AclEntry> {
    previous
        .iter()
        .filter(|old| !wanted.iter().any(|new| new.same(old)))
        .cloned()
        .collect()
}

/// The account's name for the person `person` (their Windows user name):
/// [`PREFIX`] and the name in lower case, without the characters Windows
/// refuses, cut to Windows' 20 characters.
pub fn account_name(person: &str) -> String {
    let mut name = PREFIX.to_owned();
    for c in person.chars().flat_map(char::to_lowercase) {
        if c.is_control() || FORBIDDEN.contains(&c) {
            continue;
        }
        if name.len() + c.len_utf8() > MAX_NAME {
            break;
        }
        name.push(c);
    }
    if name.len() == PREFIX.len() {
        name.push_str("agent");
    }
    name
}

/// The account's password from 32 random bytes as hex (`random_hex`): the
/// hex, then one upper-case letter, digit and symbol, so a machine whose
/// policy asks for three kinds of character takes it too. No one sees it.
pub fn password(hex: &str) -> Zeroizing<String> {
    let mut password = Zeroizing::new(String::with_capacity(hex.len() + 3));
    password.push_str(hex);
    password.push_str("A7!");
    password
}

/// Refuse a command line `CreateProcessWithLogonW` would cut: `units` UTF-16
/// units, its NUL not counted.
pub fn command_line_fits(units: usize) -> Result<()> {
    if units > COMMAND_LINE_MAX {
        bail!(
            "the agent's command line is {units} characters long; Windows starts a program as \
             another account with at most {COMMAND_LINE_MAX} (`CreateProcessWithLogonW`), so \
             it does not start: shorten its arguments"
        );
    }
    Ok(())
}

/// What `status` reads back from the system for the record's account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    /// The SID the account's name has now; `None` when no such account.
    pub sid: Option<String>,
    /// The local groups it is a member of; `None` when this process may not
    /// read them.
    pub groups: Option<Vec<String>>,
    /// The logon rights it holds or is denied; `None` when this process may
    /// not read them (the local security policy may refuse a standard user).
    pub rights: Option<Vec<String>>,
    /// Its value in [`USER_LIST_KEY`] is 0.
    pub hidden: bool,
    /// What [`RELAY_KEY`] holds for its SID.
    pub relay: Option<String>,
    /// The profile's read entry is there.
    pub profile_entry: bool,
    /// The encrypted password's file is there.
    pub password: bool,
}

/// What `seen` could not read, for `status` to name: an unelevated process
/// may not read the account's groups or rights, which only an administrator
/// can change; [`drift`] judges the rest.
pub fn unread(seen: &Observed) -> Vec<&'static str> {
    let mut out = Vec::new();
    if seen.groups.is_none() {
        out.push("its local groups");
    }
    if seen.rights.is_none() {
        out.push("its logon rights");
    }
    out
}

/// How the system differs from `record`: one line each; empty when it does
/// not. What could not be read ([`unread`]) is not judged.
pub fn drift(record: &Record, seen: &Observed) -> Vec<String> {
    let mut out = Vec::new();
    let name = &record.account;
    match &seen.sid {
        None => out.push(format!("the account {name} is gone")),
        Some(sid) if !sid.eq_ignore_ascii_case(&record.sid) => out.push(format!(
            "the account {name} has the SID {sid}, not the recorded {}",
            record.sid
        )),
        Some(_) => {}
    }
    if let Some(groups) = seen.groups.as_ref().filter(|g| !g.is_empty()) {
        out.push(format!(
            "the account {name} is in local groups ({}): it must be in none",
            groups.join(", ")
        ));
    }
    if let Some(rights) = &seen.rights {
        out.extend(rights_drift(rights));
    }
    if record.hidden && !seen.hidden {
        out.push(format!("{name} is shown on the sign-in screen again"));
    }
    let relay_ok = seen
        .relay
        .as_deref()
        .is_some_and(|p| p.eq_ignore_ascii_case(&record.person_sid));
    if record.relay_registered && !relay_ok {
        out.push(
            "the hook relay's registration of the account (HKLM\\SOFTWARE\\OpenMoat) is gone or \
             changed"
                .to_owned(),
        );
    }
    if !seen.profile_entry {
        out.push(format!(
            "the account's read entry on {} is gone",
            record.profile
        ));
    }
    if !seen.password {
        out.push("the account's encrypted password is gone".to_owned());
    }
    out
}

/// How `rights` differ from the ones setup gives: those missing, then those
/// setup did not give.
fn rights_drift(rights: &[String]) -> Vec<String> {
    let wanted: Vec<&str> = std::iter::once(INTERACTIVE_RIGHT)
        .chain(DENIED_RIGHTS)
        .collect();
    let missing: Vec<&str> = wanted
        .iter()
        .filter(|r| !rights.iter().any(|s| s.eq_ignore_ascii_case(r)))
        .copied()
        .collect();
    let extra: Vec<&str> = rights
        .iter()
        .filter(|s| !wanted.iter().any(|r| s.eq_ignore_ascii_case(r)))
        .map(String::as_str)
        .collect();
    let mut out = Vec::new();
    if !missing.is_empty() {
        out.push(format!("logon rights missing: {}", missing.join(", ")));
    }
    if !extra.is_empty() {
        out.push(format!(
            "logon rights setup did not give: {}",
            extra.join(", ")
        ));
    }
    out
}

#[cfg(test)]
mod tests;

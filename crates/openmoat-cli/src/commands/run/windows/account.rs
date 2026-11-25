//! The agent account of `openmoat run` on Windows (ADR-129): set up once by
//! an administrator (`manage.rs`: `openmoat agent-account setup|status|remove`),
//! then used by every run whose record is there and matches the system
//! ([`active`]): the run sets the account's write entries and read denies
//! ([`Active::apply`]) and starts the agent as it ([`Active::start`]).
//!
//! What decides is pure (`crate::agent_account`, `sandbox/write_token/account.rs`);
//! the Win32 calls are in this folder: `system.rs` (the account, its groups
//! and logon rights), `registry.rs` (the sign-in screen and the relay's
//! list), `logon.rs` (DPAPI, elevation, `CreateProcessWithLogonW`),
//! `filters.rs` (the network filters in the Windows Filtering Platform) and
//! `../acl.rs` (setting and taking out entries, shared with ADR-115's tier).

mod filters;
mod logon;
mod manage;
mod registry;
mod system;

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use zeroize::Zeroizing;

use super::acl;
use super::win32::Job;
use crate::agent_account::{self, AclEntry, Observed, Record};
use crate::sandbox::write_token::account::AccountPlan;
use crate::sandbox::write_token::{self, Entry};

pub use logon::AsAccount;
pub use manage::{remove, require_elevated, setup, status, supported};

/// `text` as NUL-terminated UTF-16.
fn wide(text: &str) -> Result<Vec<u16>> {
    let mut units: Vec<u16> = text.encode_utf16().collect();
    if units.contains(&0) {
        bail!("{text} holds a NUL character");
    }
    units.push(0);
    Ok(units)
}

/// A slash-separated path as the native, NUL-terminated form Win32 takes.
fn native(path: &str) -> Result<Vec<u16>> {
    wide(&path.replace('/', "\\"))
}

/// The built-in `Users` group, which `NetUserAdd` puts a new account in.
const USERS: &str = "S-1-5-32-545";

/// The agent account a run here uses: set up, and matching the system.
pub struct Active {
    pub record: Record,
    state: std::path::PathBuf,
    /// The record's network filters were read back as recorded.
    pub filters: bool,
}

/// The ports the record's network filters let the account reach, where the
/// run's proxy must listen; `None` without a record or filters. Read from
/// the record alone, before [`active`] checks the system: a proxy in the
/// range is the only one the agent could reach should the filters hold.
pub fn proxy_ports(state: &Path) -> Option<[u16; 2]> {
    Record::load(state).ok().flatten()?.wfp.map(|w| w.ports)
}

/// The agent account of the state directory `state`: `None` without a
/// record, and, with a warning, when the system no longer matches it
/// (`openmoat agent-account status` names what differs); the run is then
/// ADR-115's. The caller passes the state directory it already holds, so
/// nothing here finds a home of its own.
pub fn active(state: &Path) -> Option<Active> {
    let record = match Record::load(state) {
        Ok(record) => record?,
        Err(error) => {
            eprintln!(
                "moat run: the agent account's record cannot be read, so this run uses the \
                 write-restricted token: {error:#}"
            );
            return None;
        }
    };
    let seen = observe(state, &record);
    let drift = agent_account::drift(&record, &seen);
    if !drift.is_empty() {
        eprintln!(
            "moat run: the agent account {} no longer matches its record ({}), so this run uses \
             the write-restricted token; `openmoat agent-account status` shows it",
            record.account,
            drift.join("; ")
        );
        return None;
    }
    if seen.wfp == agent_account::wfp::Read::Unread {
        eprintln!(
            "moat run: the agent account's network filters cannot be read back from this \
             terminal, so this run does not count them (`wfp_network`); they still refuse \
             what they name"
        );
    }
    Some(Active {
        filters: matches!(seen.wfp, agent_account::wfp::Read::Seen(_)),
        record,
        state: state.to_path_buf(),
    })
}

/// What the system holds now of `record`'s account. The groups and logon
/// rights may be closed to a standard user and are then `None`, named by
/// `status` as unread; everything else that cannot be read counts as
/// missing.
fn observe(state: &Path, record: &Record) -> Observed {
    use agent_account::wfp::Read;
    let wfp = match record.wfp.as_ref().map(filters::observe) {
        None => Read::NotAsked,
        Some(Ok(seen)) => Read::Seen(seen),
        Some(Err(_)) => Read::Unread,
    };
    Observed {
        sid: system::sid_of(&record.account).ok().flatten(),
        groups: system::local_groups(&record.account).ok(),
        rights: system::rights(&record.sid).ok(),
        hidden: registry::hidden(&record.account),
        relay: registry::registered(&record.sid),
        profile_entry: has_entry(&record.profile_entry, &record.sid),
        password: state
            .join(agent_account::DIR)
            .join(agent_account::PASSWORD_FILE)
            .is_file(),
        wfp,
    }
}

/// `entry` for the account `sid` as the token's plan describes one.
fn as_entry(entry: &AclEntry, sid: &str) -> Entry {
    Entry {
        path: entry.path.clone(),
        sid: sid.to_owned(),
        allows: entry.allows,
        mask: entry.mask,
        inherit: entry.inherit,
    }
}

/// Whether `entry` for `sid` is set on its place.
fn has_entry(entry: &AclEntry, sid: &str) -> bool {
    crate::state_acl::descriptor(Path::new(&entry.path))
        .ok()
        .and_then(|d| d.aces)
        .is_some_and(|aces| !write_token::needs_change(&aces, &as_entry(entry, sid)))
}

/// Set `entry` for `sid`, unless it is there already.
fn set(entry: &AclEntry, sid: &str) -> Result<()> {
    if has_entry(entry, sid) {
        return Ok(());
    }
    acl::add_entry(
        &native(&entry.path)?,
        sid,
        (entry.allows, entry.mask, entry.inherit),
    )
    .with_context(|| format!("setting the access list of {}", entry.path))
}

/// Take `entry` for `sid` out of its place's list.
fn unset(entry: &AclEntry, sid: &str) -> Result<()> {
    let (allows, mask) = (entry.allows, entry.mask);
    acl::remove(&native(&entry.path)?, sid, &|a, m| a == allows && m == mask)
        .with_context(|| format!("taking the agent account's entry off {}", entry.path))
        .map(|_| ())
}

/// Whether this process runs as an agent account an administrator set up:
/// its token's user is a SID setup registered in HKLM, where only an
/// administrator can write (ADR-129 "The hook").
pub fn current_is_agent_account() -> bool {
    logon::current_user().is_ok_and(|sid| registry::registered(&sid).is_some())
}

impl Active {
    /// Set what `plan` needs for this run: first take out the read denies of
    /// an earlier run that this one does not set, then add the write entries
    /// and read denies that are not there yet, and record them all.
    pub fn apply(&self, plan: &AccountPlan) -> Result<()> {
        let sid = &self.record.sid;
        let mut record =
            Record::load(&self.state)?.context("the agent account's record is gone")?;
        for old in agent_account::stale(&record.read_entries, &plan.reads) {
            unset(&old, sid)?;
        }
        for entry in &plan.writes {
            if entry.allows && !has_entry(entry, sid) {
                eprintln!(
                    "moat run: granting the agent account write on {} (once per folder)",
                    entry.path
                );
            }
            set(entry, sid)?;
        }
        for entry in &plan.reads {
            set(entry, sid)?;
        }
        record.read_entries.clone_from(&plan.reads);
        record.add_writes(&plan.writes);
        crate::home::write_private(
            &self.state.join(agent_account::RECORD_FILE),
            record.to_json()?.as_bytes(),
        )
    }

    /// Start `application` as the account, suspended, in `job`. The password
    /// is decrypted for the call and cleared once it returns.
    pub fn start(
        &self,
        job: &Job,
        application: &[u16],
        line: Vec<u16>,
        env: &[u16],
    ) -> Result<AsAccount> {
        agent_account::command_line_fits(line.len().saturating_sub(1))?;
        let file = self
            .state
            .join(agent_account::DIR)
            .join(agent_account::PASSWORD_FILE);
        let blob = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
        let plain = logon::unprotect(&blob)?;
        let Ok(text) = std::str::from_utf8(&plain) else {
            bail!("the agent account's password file does not decrypt to text");
        };
        let password: Zeroizing<Vec<u16>> =
            Zeroizing::new(text.encode_utf16().chain(std::iter::once(0)).collect());
        let record = &self.record;
        logon::start(
            (&record.account, &record.sid, &password),
            job,
            application,
            line,
            env,
        )
    }
}

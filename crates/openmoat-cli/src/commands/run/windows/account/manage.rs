//! `openmoat agent-account setup`, `status` and `remove` on Windows
//! (ADR-129 §1). `commands/agent_account.rs` made the person checks and took
//! the gate's code; this file changes the machine and keeps the record.
//!
//! Setup, in order: the account (out of `Users`), its logon rights, its
//! place off the sign-in screen, its SID in the relay's list, the password
//! encrypted for the person, the read entry on the profile, the record. A
//! step that fails undoes the ones before it, so a failed setup leaves no
//! half-made account. Remove takes out what the record names, each step
//! idempotent, and keeps the record while any step fails, so running it
//! again finishes the job.

use std::io::Write as _;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context as _, Result, bail};

use super::{USERS, logon, registry, set, system, unset};
use crate::agent_account::{
    self, AclEntry, DENIED_RIGHTS, ELEVATE, INTERACTIVE_RIGHT, PROFILE_MASK, Record,
};
use crate::context::{path_string, strip_verbatim};
use crate::exit::Code;
use crate::home::Home;
use crate::render::Deferred;

/// Debug builds only: the account's name, for the end-to-end tests, which
/// must not collide with one a person set up. It must start with
/// `openmoat-`. Release builds do not read it.
#[cfg(debug_assertions)]
const NAME_VARIABLE: &str = "MOAT_TEST_AGENT_ACCOUNT";

/// Debug builds only: act as if this process were not elevated, so the
/// end-to-end tests on an elevated runner see the refusal. It can only make
/// setup refuse.
#[cfg(debug_assertions)]
const NOT_ELEVATED_VARIABLE: &str = "MOAT_TEST_NOT_ELEVATED";

/// Every supported Windows has what setup needs.
#[expect(
    clippy::unnecessary_wraps,
    reason = "one signature on every platform: elsewhere it refuses"
)]
pub fn supported() -> Result<()> {
    Ok(())
}

/// Refuse `command` unless this process runs elevated.
pub fn require_elevated(command: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var_os(NOT_ELEVATED_VARIABLE).is_some() {
        bail!("`{command}` creates a local account and changes the machine's settings: {ELEVATE}");
    }
    if !logon::elevated()? {
        bail!("`{command}` creates a local account and changes the machine's settings: {ELEVATE}");
    }
    Ok(())
}

/// The account's name for the person running this.
fn name(person_sid: &str) -> Result<String> {
    #[cfg(debug_assertions)]
    if let Ok(name) = std::env::var(NAME_VARIABLE) {
        if !name.starts_with(agent_account::PREFIX) {
            bail!("{NAME_VARIABLE} must start with {}", agent_account::PREFIX);
        }
        return Ok(name);
    }
    Ok(agent_account::account_name(&system::name_of(person_sid)?))
}

/// The person's profile, slash-separated, as the policy's `~` names it.
fn profile() -> Result<String> {
    let home = crate::home::user_home()?;
    let resolved =
        std::fs::canonicalize(&home).with_context(|| format!("resolving {}", home.display()))?;
    Ok(path_string(Path::new(&strip_verbatim(
        &resolved.to_string_lossy(),
    ))))
}

/// The state directory's list must keep the account out: only the person
/// and `SYSTEM` (ADR-083), protected, so the profile's entry never reaches it.
fn require_state_protected(state: &Path) -> Result<()> {
    let (me, sddl) = crate::state_acl::read(state)?;
    if let Err(why) = crate::state_acl::verify(&sddl, &me) {
        bail!(
            "the state directory {} lets more than you and SYSTEM in ({why}), so the agent \
             account could read it: run `openmoat doctor` and its fix first",
            state.display()
        );
    }
    Ok(())
}

pub fn setup(home: &Home) -> Result<Vec<String>> {
    let state = home.root();
    if Record::load(state)?.is_some() {
        bail!(
            "the agent account is set up already: `openmoat agent-account status` checks it; to \
             make it again, run `openmoat agent-account remove` first"
        );
    }
    require_state_protected(state)?;
    let person_sid = logon::current_user()?;
    let account = name(&person_sid)?;
    let profile = profile()?;
    let password = agent_account::password(&crate::guard_relay::random_hex(32)?);
    let wide_password: zeroize::Zeroizing<Vec<u16>> =
        zeroize::Zeroizing::new(password.encode_utf16().chain(std::iter::once(0)).collect());
    let mut out = Deferred::default();
    writeln!(out, "Creating the local account {account}…")?;
    out.flush()?;
    system::create(&account, &wide_password)?;
    let made = make(
        state,
        (&account, &person_sid, &profile),
        password.as_bytes(),
        &mut out,
    );
    let record = match made {
        Ok(record) => record,
        Err(error) => {
            // Leave nothing half-made: what `make` did is undone with the account.
            let sid = system::sid_of(&account).ok().flatten();
            if let Some(sid) = &sid {
                let entry = profile_entry(&profile);
                let _ = unset(&entry, sid);
                let _ = registry::unregister(sid);
                let _ = system::remove_rights(sid);
            }
            let _ = registry::unhide(&account);
            let _ = system::delete(&account);
            let _ = std::fs::remove_dir_all(state.join(agent_account::DIR));
            return Err(error.context("setting up the agent account; nothing was kept"));
        }
    };
    writeln!(
        out,
        "✔ agent account {} ({}): in no group, interactive logon only, hidden from the sign-in \
         screen, read on {}; `openmoat run` now starts agents as it.\n  The network is still \
         held by the proxy variables only: the network filters are the next step (ADR-129).\n  \
         Check it: openmoat agent-account status",
        record.account, record.sid, record.profile
    )?;
    out.finish()?;
    Ok(vec![
        format!("account {} ({})", record.account, record.sid),
        format!("read and run granted on {}", record.profile),
        "network filters: not set up (ADR-129, next step)".to_owned(),
    ])
}

fn profile_entry(profile: &str) -> AclEntry {
    AclEntry {
        path: profile.to_owned(),
        allows: true,
        mask: PROFILE_MASK,
        inherit: true,
    }
}

/// Every step of setup after the account exists; the record it wrote.
fn make(
    state: &Path,
    (account, person_sid, profile): (&str, &str, &str),
    password: &[u8],
    out: &mut Deferred,
) -> Result<Record> {
    let sid = system::sid_of(account)?.context("the new account has no SID")?;
    system::leave_group(USERS, &sid)?;
    let mut rights = vec![INTERACTIVE_RIGHT];
    rights.extend(DENIED_RIGHTS);
    system::add_rights(&sid, &rights)?;
    registry::hide(account)?;
    registry::register(&sid, person_sid)?;
    let encrypted = logon::protect(password)?;
    crate::home::write_private(
        &state
            .join(agent_account::DIR)
            .join(agent_account::PASSWORD_FILE),
        &encrypted,
    )?;
    let entry = profile_entry(profile);
    writeln!(
        out,
        "Granting it read on {profile}: Windows hands the entry to every file below, which \
         takes a while in a large profile…"
    )?;
    out.flush()?;
    let started = Instant::now();
    set(&entry, &sid)?;
    writeln!(out, "  done in {} s", started.elapsed().as_secs())?;
    let record = Record {
        version: agent_account::VERSION,
        account: account.to_owned(),
        sid,
        person_sid: person_sid.to_owned(),
        profile: profile.to_owned(),
        rights: vec![INTERACTIVE_RIGHT.to_owned()],
        denied_rights: DENIED_RIGHTS.iter().map(|r| (*r).to_owned()).collect(),
        hidden: true,
        relay_registered: true,
        profile_entry: entry,
        wfp: None,
        write_entries: Vec::new(),
        read_entries: Vec::new(),
    };
    crate::home::write_private(
        &state.join(agent_account::RECORD_FILE),
        record.to_json()?.as_bytes(),
    )?;
    Ok(record)
}

pub fn status(home: &Home) -> Result<Code> {
    let mut out = Deferred::default();
    let Some(record) = Record::load(home.root())? else {
        let person = logon::current_user()?;
        let leftover = name(&person)
            .ok()
            .filter(|n| system::sid_of(n).ok().flatten().is_some());
        if let Some(name) = leftover {
            writeln!(
                out,
                "✘ a local account {name} exists, but no record of OpenMoat's names it: delete \
                 it with `net user {name} /delete` from an administrator terminal, or keep it if \
                 it is not OpenMoat's"
            )?;
            out.finish()?;
            return Ok(Code::Failed);
        }
        writeln!(
            out,
            "· no agent account: `openmoat run` here uses the write-restricted token (ADR-115), \
             and reads are the hook's; `openmoat agent-account setup`, from an administrator \
             terminal, adds it"
        )?;
        out.finish()?;
        return Ok(Code::Ok);
    };
    let seen = super::observe(home.root(), &record);
    let drift = agent_account::drift(&record, &seen);
    if drift.is_empty() {
        writeln!(
            out,
            "✔ agent account {} ({}): matches its record; `openmoat run` starts agents as it\n  \
             {} write entries and {} read denies from runs; network filters: not set up (the \
             next step of ADR-129)",
            record.account,
            record.sid,
            record.write_entries.len(),
            record.read_entries.len()
        )?;
        let unread = agent_account::unread(&seen);
        if !unread.is_empty() {
            writeln!(
                out,
                "  · not readable from this terminal: {}; run it from an administrator \
                 terminal to check them too",
                unread.join(" and ")
            )?;
        }
        out.finish()?;
        return Ok(Code::Ok);
    }
    writeln!(
        out,
        "✘ agent account {}: the system differs from its record, so `openmoat run` uses the \
         write-restricted token until it matches:",
        record.account
    )?;
    for line in &drift {
        writeln!(out, "  - {line}")?;
    }
    writeln!(
        out,
        "  `openmoat agent-account remove`, then `setup`, makes it again"
    )?;
    out.finish()?;
    Ok(Code::Failed)
}

pub fn remove(home: &Home) -> Result<Option<Vec<String>>> {
    let state = home.root();
    let mut out = Deferred::default();
    let Some(record) = Record::load(state)? else {
        writeln!(out, "· no agent account is set up; nothing to remove")?;
        out.finish()?;
        return Ok(None);
    };
    let sid = &record.sid;
    let mut failed = Vec::new();
    let mut step = |what: &str, done: Result<()>| {
        if let Err(error) = done {
            failed.push(format!("{what}: {error:#}"));
        }
    };
    for entry in record.entries() {
        step(&format!("the entry on {}", entry.path), unset(entry, sid));
    }
    step(
        "the sign-in screen's list",
        registry::unhide(&record.account),
    );
    step("the hook relay's list", registry::unregister(sid));
    step("the logon rights", system::remove_rights(sid));
    step("the account's profile", logon::delete_profile(sid));
    step("the account", system::delete(&record.account));
    if !failed.is_empty() {
        bail!(
            "the agent account is not fully removed; its record is kept, so `openmoat \
             agent-account remove` again finishes it:\n  {}",
            failed.join("\n  ")
        );
    }
    match std::fs::remove_dir_all(state.join(agent_account::DIR)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).context("removing the account's password");
        }
        _ => {}
    }
    std::fs::remove_file(state.join(agent_account::RECORD_FILE))
        .context("removing the agent account's record")?;
    writeln!(
        out,
        "✔ agent account {} removed with its profile and the {} entries it had; `openmoat run` \
         uses the write-restricted token again",
        record.account,
        record.entries().count()
    )?;
    out.finish()?;
    Ok(Some(vec![
        format!("account {} ({}) deleted", record.account, record.sid),
        format!("{} access-list entries taken out", record.entries().count()),
    ]))
}

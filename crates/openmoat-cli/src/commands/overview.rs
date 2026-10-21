//! `moat` with no subcommand: one health line, then whatever needs a person.
//!
//! The questions are asked only at a terminal; the answers run the same code as
//! `moat doctor --accept` and `moat allow`, checks included. Without a terminal
//! (a hook, a script, an agent's shell) it prints the command to run and changes
//! nothing.

use std::io::{self, Write as _};

use anyhow::{Context as _, Result};
use openmoat_audit::Event;
use openmoat_core::{Action, Verdict};
use openmoat_hosts::Host;

use crate::approvals::{self, Grants, Overlay};
use crate::cli::{DoctorArgs, UpgradeArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::Lock;
use crate::render;

const MS_PER_DAY: i64 = 86_400_000;

pub fn run() -> Result<Code> {
    let home = Home::locate()?;
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        println!("OpenMoat is not set up here; run `openmoat init`.");
        return Ok(Code::Usage);
    }
    let person = crate::terminal::person();
    let now = crate::time::now_ms();
    let today = now - now.rem_euclid(MS_PER_DAY);
    let store = home.open_audit()?;
    println!("{}", health(&home, &store.since(today, None)?)?);

    let drift = Lock::load(&lock_path)?.verify();
    if !drift.is_empty() {
        for d in &drift {
            println!("✗ lock  {d}");
        }
        if !person {
            println!("A person must accept these at a terminal: `openmoat doctor --accept`.");
            return Ok(Code::Usage);
        }
        if !matches!(
            answer("Accept these changes? [y/N] ")?.as_str(),
            "y" | "yes"
        ) {
            println!("Nothing changed; every call is denied until a person accepts.");
            println!("Run `openmoat doctor` to look at the changes.");
            return Ok(Code::Usage);
        }
        let code = super::doctor::run(&DoctorArgs {
            accept: true,
            verbose: false,
            format: crate::cli::Format::Text,
            bundle: None,
            bundle_events: 20,
        })?;
        if !Lock::load(&lock_path)?.verify().is_empty() {
            return Ok(code);
        }
    }

    let update = crate::upgrade::available(&home);
    if let Some(update) = &update
        && let Some(code) = offer_upgrade(update, person)?
    {
        return Ok(code);
    }

    let Some((event, host, action)) = pending_ask(&home, &store, today, now)? else {
        if update.is_none() {
            println!("Nothing needs you.");
        }
        println!("`openmoat show` lists recent decisions; `openmoat --help` lists every command.");
        return Ok(Code::Ok);
    };
    let asked = format!(
        "{} asked to {} (rule {}, session {})",
        host.display_name(),
        approvals::describe(&action),
        event.rules.join(", "),
        event.session_id
    );
    println!("{}", render::clean(&asked));
    if !person {
        println!("A person can allow it at a terminal: `openmoat allow --last` for this session,");
        println!("`openmoat allow --last --always` for good.");
        return Ok(Code::Ok);
    }
    let always = match answer("Allow? [o]nce for this session / [a]lways / [n]o ")?.as_str() {
        "o" | "once" => false,
        "a" | "always" => true,
        _ => {
            println!("Nothing changed.");
            return Ok(Code::Ok);
        }
    };
    // The exact ask shown, not `--last`: a newer ask may have arrived meanwhile.
    super::allow::run_for(&event, &action, always)
}

/// Say when the default has changes the policy can take; at a terminal, offer
/// `moat policy upgrade`, which shows the diff and asks again before writing.
/// `Some` when the person went into it.
fn offer_upgrade(update: &str, person: bool) -> Result<Option<Code>> {
    println!("Policy update available: {update}.");
    if !person {
        println!("A person can review and apply it at a terminal: `openmoat policy upgrade`.");
        return Ok(None);
    }
    if !matches!(answer("See the changes? [y/N] ")?.as_str(), "y" | "yes") {
        return Ok(None);
    }
    super::policy::upgrade(&UpgradeArgs {
        dry_run: false,
        yes: false,
        undo: false,
    })
    .map(Some)
}

/// Agents whose hook is installed, with their protection level, and today's decisions.
fn health(home: &Home, today: &[Event]) -> Result<String> {
    let binary = crate::install::hook_binary()?;
    let protected: Vec<String> = crate::protection::report(home, &binary)?
        .into_iter()
        .filter(|agent| agent.level.hooked())
        .map(|agent| format!("{} ({})", agent.name, agent.level.label()))
        .collect();
    let agents = if protected.is_empty() {
        "No agent is protected (run `openmoat init`)".to_owned()
    } else {
        format!("Protecting {}", protected.join(", "))
    };
    let count = |v: Verdict| today.iter().filter(|e| e.verdict == v).count();
    Ok(format!(
        "{agents} · today: {} decision{}, {} denied, {} asked",
        today.len(),
        if today.len() == 1 { "" } else { "s" },
        count(Verdict::Deny),
        count(Verdict::Ask)
    ))
}

/// The ask `moat allow --last` would take, if it is from today and no grant or
/// permanent rule already covers it.
fn pending_ask(
    home: &Home,
    store: &openmoat_audit::Store,
    today: i64,
    now: i64,
) -> Result<Option<(Event, Host, Action)>> {
    let Some(event) = super::allow::newest_ask(store)?.filter(|e| e.ts_ms >= today) else {
        return Ok(None);
    };
    let action = super::allow::asked(&event)?;
    let host: Host = event.host.parse()?;
    // As `moat allow` binds it: an ask recorded without a working directory
    // is approved in the current one.
    let cwd = match event.cwd.as_deref() {
        Some(cwd) => crate::context::absolute(std::path::Path::new(cwd))?,
        None => std::env::current_dir()?,
    };
    let project = approvals::project_of(&cwd, &crate::home::user_home()?);
    let scope = approvals::Scope {
        host: &event.host,
        session_id: &event.session_id,
        project: &project,
    };
    let granted = Grants::load(&home.grants_path())?.matches(scope, &action, now);
    let permanent = Overlay::load(&home.overlay_path())?.covers(&action);
    Ok((!granted && !permanent).then_some((event, host, action)))
}

/// Ask a question and read one line; end of input reads as an empty answer.
fn answer(question: &str) -> Result<String> {
    print!("{question}");
    io::stdout().flush()?;
    let line = crate::terminal::read_answer().context("reading the answer")?;
    Ok(line.trim().to_ascii_lowercase())
}

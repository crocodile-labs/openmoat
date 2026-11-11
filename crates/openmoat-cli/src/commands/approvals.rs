//! `openmoat approvals`: answering reviews from another device (ADR-078).
//! Every command but `status` is a person's, as `openmoat allow` is: it
//! refuses without a terminal and with an agent among its parents, so an
//! agent can neither connect a channel, add an approver nor answer.
//!
//! No command names a channel: each takes it from the registry
//! ([`crate::remote::REGISTRY`]) and the settings.

use std::io::Write as _;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};

use crate::cli::{ApprovalsStatusArgs, ApproverArgs, ConnectArgs, Format};
use crate::exit::Code;
use crate::home::Home;
use crate::proxy_session::Key;
use crate::remote::{
    AuditRecords, Credential, DEFAULT_EXPIRY_S, Listener, MAX_EXPIRY_S, MIN_EXPIRY_S, Options,
    REGISTRY, Settings, Spec, Store,
};
use crate::render::Deferred;

/// How long one poll of the channel waits for a reply.
const POLL: Duration = Duration::from_secs(25);
/// The pause after a failed round, so a channel that is down is not hammered.
const BACKOFF: Duration = Duration::from_secs(5);

fn person(command: &str) -> Result<()> {
    crate::terminal::refuse_agent(command)?;
    if !crate::terminal::interactive() {
        bail!("`{command}` must be run by a person in a terminal, not from a hook or script");
    }
    Ok(())
}

fn store() -> Result<(Home, Store)> {
    let home = Home::locate()?;
    home.require_exists()?;
    let store = Store::of(&home);
    Ok((home, store))
}

/// How to connect one, for messages: the registry's names.
fn how_to_connect() -> String {
    format!(
        "`openmoat approvals connect <{}>` sets one up",
        REGISTRY.names().join("|")
    )
}

/// The key and settings of a connected channel.
fn connected(store: &Store) -> Result<(Key, Settings)> {
    if !store.connected() {
        bail!("no channel is connected; {}", how_to_connect());
    }
    let key = Key::load(&store.key_path())?;
    let settings = Settings::load(&store.settings_path(), &key)?;
    Ok((key, settings))
}

/// A line the person types at the terminal, after `ask`.
fn ask(ask: &str) -> Result<String> {
    eprint!("{ask}");
    std::io::stderr().flush()?;
    Ok(crate::terminal::read_answer()?.trim().to_owned())
}

/// The answers to `spec`'s questions: from `--set`, else asked.
fn options(spec: &Spec, given: &[String]) -> Result<Options> {
    let mut options = Options::new();
    for pair in given {
        let (key, value) = pair
            .split_once('=')
            .with_context(|| format!("--set {pair} is not KEY=VALUE"))?;
        options.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    for question in spec.questions {
        if !options.contains_key(question.key) {
            options.insert(question.key.to_owned(), ask(question.ask)?);
        }
    }
    Ok(options)
}

/// `openmoat approvals connect <channel>`.
pub fn connect(args: &ConnectArgs) -> Result<Code> {
    person("openmoat approvals connect")?;
    let spec = REGISTRY.find(&args.channel)?;
    let expiry_s = match &args.expires {
        None => DEFAULT_EXPIRY_S,
        Some(text) => crate::time::parse_span(text)
            .map(|ms| u64::try_from(ms / 1000).unwrap_or(0))
            .filter(|s| (MIN_EXPIRY_S..=MAX_EXPIRY_S).contains(s))
            .with_context(|| {
                format!("--expires {text} is not a span of 1 to 60 minutes, such as `5m`")
            })?,
    };
    let (_home, store) = store()?;
    let credential = if let Some(path) = &args.credential_file {
        Credential::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?
                .trim()
                .to_owned(),
        )
    } else {
        Credential::new(ask(spec.ask_credential)?)
    };
    let options = options(spec, &args.options)?;
    let account = crate::remote::connect(&store, spec, &credential, options, expiry_s)?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "connected {} as {account}; its credential is in {} (owner-only)",
        spec.title,
        store.channel(spec).credential_path().display()
    )?;
    if let Some(path) = &args.credential_file {
        writeln!(out, "you can delete {} now", path.display())?;
    }
    writeln!(
        out,
        "next:\n{}\nrequests wait {} minute(s) for an answer",
        (spec.next_steps)(&account),
        expiry_s / 60
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `openmoat approvals allow <id>`.
pub fn allow(args: &ApproverArgs) -> Result<Code> {
    person("openmoat approvals allow")?;
    let (_home, store) = store()?;
    let (key, mut settings) = connected(&store)?;
    let spec = REGISTRY.find(&settings.channel)?;
    let id = REGISTRY.approver(spec, &args.user_id)?;
    let mut out = Deferred::default();
    if settings.approver(&id) {
        writeln!(out, "{id} can already approve")?;
    } else {
        settings.approvers.push(id.clone());
        settings.save(&store.settings_path(), &key)?;
        writeln!(
            out,
            "{id} can now approve calls held for review on this machine; `openmoat approvals \
             remove {id}` takes that back"
        )?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// `openmoat approvals remove <id>`.
pub fn remove(args: &ApproverArgs) -> Result<Code> {
    person("openmoat approvals remove")?;
    let (_home, store) = store()?;
    let (key, mut settings) = connected(&store)?;
    let spec = REGISTRY.find(&settings.channel)?;
    let id = REGISTRY.approver(spec, &args.user_id)?;
    if !settings.approver(&id) {
        bail!("{id} is not an approver");
    }
    settings.approvers.retain(|a| a != &id);
    settings.save(&store.settings_path(), &key)?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "{id} can no longer approve; answers it gave that are not used yet no longer count"
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// What `status` reports of a connected channel.
struct State {
    settings: Settings,
    account: Option<String>,
    waiting: usize,
    problem: Option<String>,
}

fn state(store: &Store) -> Result<State> {
    let (key, settings) = connected(store)?;
    let now = crate::time::now_ms();
    let waiting = store
        .requests()
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .filter(|r| r.verified(&key) && !r.expired(now))
        .count();
    let (account, problem) = match REGISTRY.find(&settings.channel) {
        Ok(spec) => (
            crate::remote::account(store, &REGISTRY, &key, &settings),
            crate::remote::credential_problem(store, spec),
        ),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    Ok(State {
        settings,
        account,
        waiting,
        problem,
    })
}

/// `openmoat approvals status`: read-only, so no terminal is needed.
pub fn status(args: &ApprovalsStatusArgs) -> Result<Code> {
    let (_home, store) = store()?;
    let state = if store.connected() {
        state(&store)
    } else {
        Err(anyhow::Error::msg("no channel connected"))
    };
    if args.format == Format::Json {
        let value = match &state {
            Ok(s) => serde_json::json!({
                "connected": true,
                "channel": s.settings.channel,
                "account": s.account,
                "approvers": s.settings.approvers,
                "expiry_s": s.settings.expiry_s,
                "waiting": s.waiting,
                "problem": s.problem,
            }),
            Err(error) => serde_json::json!({
                "connected": false,
                "problem": store.connected().then(|| format!("{error:#}")),
            }),
        };
        crate::render::json(&value)?;
        return Ok(Code::Ok);
    }
    let mut out = Deferred::default();
    match state {
        Ok(s) => {
            match &s.account {
                Some(account) => writeln!(out, "channel: {} ({account})", s.settings.channel)?,
                None => writeln!(out, "channel: {}", s.settings.channel)?,
            }
            if s.settings.approvers.is_empty() {
                writeln!(
                    out,
                    "approvers: none yet; `openmoat approvals allow <user id>` adds one"
                )?;
            } else {
                writeln!(out, "approvers: {}", s.settings.approvers.join(", "))?;
            }
            writeln!(out, "requests wait: {} minute(s)", s.settings.expiry_s / 60)?;
            writeln!(out, "waiting now: {}", s.waiting)?;
            if let Some(problem) = s.problem {
                writeln!(out, "problem: {problem}")?;
            }
            writeln!(
                out,
                "answers arrive only while `openmoat approvals listen` runs"
            )?;
        }
        Err(_) if !store.connected() => writeln!(
            out,
            "no channel connected: reviews are answered where the agent runs; {}",
            how_to_connect()
        )?,
        Err(error) => writeln!(
            out,
            "channel settings unusable, so no remote answer is accepted: {error:#}"
        )?,
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// `openmoat approvals test`.
pub fn test() -> Result<Code> {
    person("openmoat approvals test")?;
    let (_home, store) = store()?;
    let (key, settings) = connected(&store)?;
    if settings.approvers.is_empty() {
        bail!("no approver yet; `openmoat approvals allow <user id>` adds one");
    }
    let (spec, mut channel) = crate::remote::open(&store, &REGISTRY, &key, &settings)?;
    let mut out = Deferred::default();
    let mut failed = false;
    for approver in &settings.approvers {
        let Some(local) = crate::remote::channel::local_id(spec.name, approver) else {
            continue;
        };
        match channel.notify(
            local,
            "OpenMoat: a test message. Calls held for review on this machine will come here \
             while `openmoat approvals listen` runs.",
        ) {
            Ok(()) => writeln!(out, "sent to {approver}")?,
            Err(error) => {
                failed = true;
                writeln!(out, "could not reach {approver}: {error:#}")?;
            }
        }
    }
    out.finish()?;
    Ok(if failed { Code::Failed } else { Code::Ok })
}

/// `openmoat approvals listen`: until Ctrl-C.
pub fn listen() -> Result<Code> {
    person("openmoat approvals listen")?;
    let (home, store) = store()?;
    let (key, settings) = connected(&store)?;
    let (spec, mut channel) = crate::remote::open(&store, &REGISTRY, &key, &settings)?;
    let mut records = AuditRecords { home: &home };
    let mut listener = Listener::new(&store, &key, spec, settings);
    eprintln!(
        "listening for answers over {}; Ctrl-C stops (requests then wait unanswered and expire)",
        spec.title
    );
    loop {
        // Approvers a person changed meanwhile, and a channel disconnected.
        match connected(&store) {
            Ok((_, settings)) if settings.channel != spec.name => {
                bail!("stopped: another channel was connected; run `listen` again")
            }
            Ok((_, settings)) => listener.update(settings),
            Err(error) => bail!("stopped: {error:#}"),
        }
        let round = listener.step(channel.as_mut(), &mut records, POLL, &crate::time::now_ms);
        for line in listener.log.drain(..) {
            eprintln!("{} {line}", crate::time::clock(crate::time::now_ms()));
        }
        if let Err(error) = round {
            eprintln!("moat: {error:#}; trying again in {} s", BACKOFF.as_secs());
            std::thread::sleep(BACKOFF);
        }
    }
}

/// `openmoat approvals disconnect`.
pub fn disconnect() -> Result<Code> {
    person("openmoat approvals disconnect")?;
    let (_home, store) = store()?;
    let (was, removed) = crate::remote::disconnect(&store, &REGISTRY)?;
    let mut out = Deferred::default();
    if removed {
        write!(
            out,
            "disconnected: reviews are answered only where the agent runs"
        )?;
        match was {
            Some(spec) => writeln!(out, "; {}", spec.revoke)?,
            None => writeln!(out)?,
        }
    } else {
        writeln!(out, "no channel was connected")?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

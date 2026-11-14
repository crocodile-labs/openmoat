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

use crate::cli::{ApprovalsStatusArgs, ApproverArgs, ConnectArgs, Format, WaitArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::proxy_session::Key;
use crate::remote::{
    AuditRecords, Credential, DEFAULT_EXPIRY_S, Listener, MAX_EXPIRY_S, MIN_EXPIRY_S, Options,
    REGISTRY, Secrets, Settings, Spec, Store,
};
use crate::render::Deferred;

/// How long one poll of the channel waits for a reply.
const POLL: Duration = Duration::from_secs(25);
/// The same while the hook waits for answers (ADR-093): a request the guard
/// writes during a poll is sent when the poll ends, so polls are short.
const POLL_WHILE_WAITING: Duration = Duration::from_secs(2);
const _: () = assert!(
    POLL_WHILE_WAITING.as_secs() * 4 < crate::remote::live::LIVE_MS.unsigned_abs() / 1000,
    "several rounds fit in a beat's life"
);
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

/// `spec`'s fields: settings from `--set`, the one secret from
/// `--credential-file`, and every other one asked at the terminal. A secret
/// is never taken from the command line, which other programs can read.
fn fields(spec: &Spec, args: &ConnectArgs) -> Result<(Secrets, Options)> {
    let mut secrets = Secrets::new();
    let mut options = Options::new();
    for pair in &args.options {
        let (key, value) = pair
            .split_once('=')
            .with_context(|| format!("--set {pair} is not KEY=VALUE"))?;
        let key = key.trim();
        if spec.fields.iter().any(|f| f.secret && f.key == key) {
            bail!(
                "`{key}` is a secret: it is asked at the terminal or read with \
                 --credential-file, never given on the command line"
            );
        }
        options.insert(key.to_owned(), value.trim().to_owned());
    }
    if let Some(path) = &args.credential_file {
        let mut secret = spec.fields.iter().filter(|f| f.secret);
        let (Some(only), None) = (secret.next(), secret.next()) else {
            bail!(
                "--credential-file reads one secret; {} takes another number, asked at \
                 the terminal",
                spec.title
            );
        };
        let text = Credential::new(
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        );
        secrets.insert(only.key.to_owned(), Credential::new(text.trim().to_owned()));
    }
    for field in spec.fields {
        let have = if field.secret {
            secrets.contains_key(field.key)
        } else {
            options.contains_key(field.key)
        };
        if have {
            continue;
        }
        let answer = Credential::new(ask(field.ask)?);
        if field.secret {
            secrets.insert(field.key.to_owned(), answer);
        } else {
            options.insert(field.key.to_owned(), answer.to_string());
        }
    }
    Ok((secrets, options))
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
    let (secrets, options) = fields(spec, args)?;
    let account = crate::remote::connect(&store, spec, &secrets, options, expiry_s)?;
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
    /// Whether a listener's beat is fresh ([`crate::remote::live`]).
    listening: bool,
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
    let listening = crate::remote::live::live(store, &key, &settings.channel, now);
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
        listening,
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
                "wait_s": s.settings.wait().as_secs(),
                "listening": s.listening,
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
            match s.settings.wait().as_secs() {
                0 => writeln!(
                    out,
                    "the hook waits: no (`openmoat approvals wait <seconds>`)"
                )?,
                wait => writeln!(
                    out,
                    "the hook waits: up to {wait} s while the listener runs ({})",
                    if s.listening {
                        "running now"
                    } else {
                        "not running now"
                    }
                )?,
            }
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
    // A listener that stops says so at once, not when its beat is stale
    // (Ctrl-C ends the process without this, and the beat goes stale).
    let _stopped = Stopped(&store);
    eprintln!(
        "listening for answers over {}; Ctrl-C stops (requests then wait unanswered and expire)",
        spec.title
    );
    loop {
        // Approvers a person changed meanwhile, and a channel disconnected.
        let poll = match connected(&store) {
            Ok((_, settings)) if settings.channel != spec.name => {
                bail!("stopped: another channel was connected; run `listen` again")
            }
            Ok((_, settings)) => {
                let poll = poll_for(&settings);
                listener.update(settings);
                poll
            }
            Err(error) => bail!("stopped: {error:#}"),
        };
        let round = listener.step(channel.as_mut(), &mut records, poll, &crate::time::now_ms);
        for line in listener.log.drain(..) {
            eprintln!("{} {line}", crate::time::clock(crate::time::now_ms()));
        }
        if let Err(error) = round {
            eprintln!("moat: {error:#}; trying again in {} s", BACKOFF.as_secs());
            std::thread::sleep(BACKOFF);
        }
    }
}

/// How long each poll of the channel waits under `settings`.
fn poll_for(settings: &Settings) -> Duration {
    if settings.wait().is_zero() {
        POLL
    } else {
        POLL_WHILE_WAITING
    }
}

/// Removes the listener's beat when `listen` returns.
struct Stopped<'a>(&'a Store);

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        crate::remote::live::stop(self.0);
    }
}

/// `openmoat approvals wait <seconds>`: how long the hook waits for an answer
/// while `listen` runs (ADR-093); `0` never waits.
pub fn wait(args: &WaitArgs) -> Result<Code> {
    person("openmoat approvals wait")?;
    let (_home, store) = store()?;
    let (key, mut settings) = connected(&store)?;
    settings.set_wait(args.seconds)?;
    settings.save(&store.settings_path(), &key)?;
    let mut out = Deferred::default();
    if args.seconds == 0 {
        writeln!(
            out,
            "the hook no longer waits: an approval from {} runs the call on its next try",
            settings.channel
        )?;
    } else {
        writeln!(
            out,
            "while `openmoat approvals listen` runs, the hook waits up to {} s for an answer \
             (less where the agent's hook time limit or the guard's own budget leaves less)",
            args.seconds
        )?;
    }
    out.finish()?;
    Ok(Code::Ok)
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

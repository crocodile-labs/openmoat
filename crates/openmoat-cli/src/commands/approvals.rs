//! `openmoat approvals`: answering reviews from another device (ADR-078).
//! Every command but `status` is a person's, as `openmoat allow` is: it
//! refuses without a terminal and with an agent among its parents, so an
//! agent can neither connect a channel, add an approver nor answer.

use std::io::Write as _;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use zeroize::Zeroizing;

use crate::cli::{ApprovalsStatusArgs, ApproverArgs, ChannelKind, ConnectArgs, Format};
use crate::exit::Code;
use crate::home::Home;
use crate::proxy_session::Key;
use crate::remote::telegram::{self, Https, Telegram};
use crate::remote::{
    AuditRecords, Channel as _, DEFAULT_EXPIRY_S, Listener, MAX_EXPIRY_S, MIN_EXPIRY_S, Settings,
    Store,
};
use crate::render::Deferred;

/// How long one `getUpdates` waits for a reply.
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

/// The key and settings of a connected channel.
fn connected(store: &Store) -> Result<(Key, Settings)> {
    if !store.connected() {
        bail!("no channel is connected; `openmoat approvals connect telegram` sets one up");
    }
    let key = Key::load(&store.key_path())?;
    let settings = Settings::load(&store.settings_path(), &key)?;
    Ok((key, settings))
}

fn channel(store: &Store, settings: &Settings) -> Result<Telegram<Https>> {
    if settings.channel != telegram::NAME {
        bail!(
            "this release does not know the channel `{}`",
            settings.channel
        );
    }
    let token = telegram::read_token(&store.token_path(telegram::NAME))?;
    Ok(Telegram::new(Https::new(token)?))
}

/// `openmoat approvals connect telegram`.
pub fn connect(args: &ConnectArgs) -> Result<Code> {
    person("openmoat approvals connect")?;
    let ChannelKind::Telegram = args.channel;
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
    let token = if let Some(path) = &args.token_file {
        Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?
                .trim()
                .to_owned(),
        )
    } else {
        eprint!("Paste the bot's token from @BotFather, then Enter: ");
        std::io::stderr().flush()?;
        Zeroizing::new(crate::terminal::read_answer()?.trim().to_owned())
    };
    if !telegram::valid_token(&token) {
        bail!("that is not a Telegram bot token (`<digits>:<letters>`); nothing was saved");
    }
    let bot = Telegram::new(Https::new(token.clone())?)
        .bot_name()
        .context("checking the token with Telegram; nothing was saved")?;
    let key = Key::load_or_create_at(&store.key_path())?;
    crate::home::write_private(&store.token_path(telegram::NAME), token.as_bytes())?;
    // Approvers stay when the same channel is connected again.
    let mut settings = Settings::new(telegram::NAME, expiry_s)?;
    if let Ok(old) = Settings::load(&store.settings_path(), &key)
        && old.channel == settings.channel
    {
        settings.approvers = old.approvers;
    }
    settings.save(&store.settings_path(), &key)?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "connected the Telegram bot {bot}; its token is in {} (owner-only)",
        store.token_path(telegram::NAME).display()
    )?;
    if let Some(path) = &args.token_file {
        writeln!(out, "you can delete {} now", path.display())?;
    }
    writeln!(
        out,
        "next:\n  1. send /start to {bot} from your own Telegram account\n  2. run \
         `openmoat approvals listen` in a terminal of your own; it prints your user id when \
         you message the bot\n  3. `openmoat approvals allow <your user id>`, then \
         `openmoat approvals test`\nrequests wait {} minute(s) for an answer",
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
    if !telegram::valid_user(&args.user_id) {
        bail!("`{}` is not a Telegram user id (a number)", args.user_id);
    }
    let mut out = Deferred::default();
    if settings.approver(&args.user_id) {
        writeln!(out, "{} can already approve", args.user_id)?;
    } else {
        settings.approvers.push(args.user_id.clone());
        settings.save(&store.settings_path(), &key)?;
        writeln!(
            out,
            "{} can now approve calls held for review on this machine; `openmoat approvals \
             remove {}` takes that back",
            args.user_id, args.user_id
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
    if !settings.approver(&args.user_id) {
        bail!("{} is not an approver", args.user_id);
    }
    settings.approvers.retain(|a| a != &args.user_id);
    settings.save(&store.settings_path(), &key)?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "{} can no longer approve; answers it gave that are not used yet no longer count",
        args.user_id
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `openmoat approvals status`: read-only, so no terminal is needed.
pub fn status(args: &ApprovalsStatusArgs) -> Result<Code> {
    let (_home, store) = store()?;
    let now = crate::time::now_ms();
    let state = if store.connected() {
        connected(&store).map(|(key, settings)| {
            let waiting = store
                .requests()
                .unwrap_or_default()
                .into_iter()
                .flatten()
                .filter(|r| r.verified(&key) && !r.expired(now))
                .count();
            let token = store.token_path(&settings.channel);
            let problem = if token.exists() {
                crate::key_file::problem(&token)
            } else {
                Some(format!("{} is missing", token.display()))
            };
            (settings, waiting, problem)
        })
    } else {
        Err(anyhow::Error::msg("no channel connected"))
    };
    if args.format == Format::Json {
        let value = match &state {
            Ok((settings, waiting, problem)) => serde_json::json!({
                "connected": true,
                "channel": settings.channel,
                "approvers": settings.approvers,
                "expiry_s": settings.expiry_s,
                "waiting": waiting,
                "problem": problem,
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
        Ok((settings, waiting, problem)) => {
            writeln!(out, "channel: {}", settings.channel)?;
            if settings.approvers.is_empty() {
                writeln!(
                    out,
                    "approvers: none yet; `openmoat approvals allow <user id>` adds one"
                )?;
            } else {
                writeln!(out, "approvers: {}", settings.approvers.join(", "))?;
            }
            writeln!(out, "requests wait: {} minute(s)", settings.expiry_s / 60)?;
            writeln!(out, "waiting now: {waiting}")?;
            if let Some(problem) = problem {
                writeln!(out, "problem: {problem}")?;
            }
            writeln!(
                out,
                "answers arrive only while `openmoat approvals listen` runs"
            )?;
        }
        Err(_) if !store.connected() => writeln!(
            out,
            "no channel connected: reviews are answered where the agent runs; \
             `openmoat approvals connect telegram` sets one up"
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
    let (_key, settings) = connected(&store)?;
    if settings.approvers.is_empty() {
        bail!("no approver yet; `openmoat approvals allow <user id>` adds one");
    }
    let mut channel = channel(&store, &settings)?;
    let mut out = Deferred::default();
    let mut failed = false;
    for approver in &settings.approvers {
        match channel.notify(
            approver,
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
    let mut channel = channel(&store, &settings)?;
    let mut records = AuditRecords { home: &home };
    let mut listener = Listener::new(&store, &key, settings);
    eprintln!(
        "listening for answers over {}; Ctrl-C stops (requests then wait unanswered and expire)",
        channel.name()
    );
    loop {
        // Approvers a person changed meanwhile, and a channel disconnected.
        match connected(&store) {
            Ok((_, settings)) => listener.update(settings),
            Err(error) => bail!("stopped: {error:#}"),
        }
        let round = listener.step(&mut channel, &mut records, POLL, &crate::time::now_ms);
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
    let mut removed = false;
    for path in [store.settings_path(), store.token_path(telegram::NAME)] {
        match std::fs::remove_file(&path) {
            Ok(()) => removed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
    for dir in ["requests", "answers"] {
        let _ = std::fs::remove_dir_all(store.dir().join(dir));
    }
    let mut out = Deferred::default();
    if removed {
        writeln!(
            out,
            "disconnected: reviews are answered only where the agent runs; revoke the bot's \
             token with @BotFather if it may have been seen"
        )?;
    } else {
        writeln!(out, "no channel was connected")?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

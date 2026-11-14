//! `openmoat approvals listen`: at a person's terminal until Ctrl-C, or as the
//! user service `openmoat approvals install` writes (`--service`, ADR-094).
//!
//! A person's listener stops when the channel goes away; the service's waits
//! for one instead, so `disconnect` and `connect` do not need the service
//! reinstalled. Either way only one listener runs per state directory: two
//! would each send every request and race for the channel's replies.

use std::ffi::OsString;
use std::fs::{File, TryLockError};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};

use super::{connected, person, store};
use crate::cli::ListenArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::proxy_session::Key;
use crate::remote::listen::run::{self, Shared};
use crate::remote::{AuditRecords, Listener, REGISTRY, Settings, Spec, Store};

/// How long the service waits before it looks again for a channel, or for the
/// listener that holds the lock to stop.
const IDLE: Duration = Duration::from_secs(30);
/// The command, as refusals name it.
const COMMAND: &str = "openmoat approvals listen";

/// Variables that change what the listener trusts or loads: the TLS roots it
/// checks the channel's server with (`rustls-native-certs` reads the first
/// two) and the dynamic loader's injection points. A person's shell may set
/// them; nothing sets them for the service but a change to the user's service
/// environment (`launchctl setenv`, `systemctl --user set-environment`), so
/// the service refuses to start with one.
const STEERING: &[&str] = &[
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
];
/// Every variable with this prefix steers macOS's dynamic loader.
const STEERING_PREFIX: &str = "DYLD_";

/// Which of `names` steer the listener ([`STEERING`]), sorted.
pub fn steering(names: impl Iterator<Item = OsString>) -> Vec<String> {
    let mut found: Vec<String> = names
        .filter_map(|name| name.into_string().ok())
        .filter(|name| STEERING.contains(&name.as_str()) || name.starts_with(STEERING_PREFIX))
        .collect();
    found.sort();
    found
}

/// `--service`: refused unless no agent started it, its environment steers
/// nothing, the installed service file is exactly what `install` writes, and
/// the service manager started it. No terminal is needed: the service manager
/// gives none.
fn service_launch(home: &Home) -> Result<()> {
    crate::terminal::refuse_agent(COMMAND)?;
    let steered = steering(std::env::vars_os().map(|(name, _)| name));
    if !steered.is_empty() {
        bail!(
            "`{COMMAND} --service` refuses to start with {} set: the service's environment \
             was changed (`launchctl setenv` or `systemctl --user set-environment`); unset \
             it there",
            steered.join(", ")
        );
    }
    crate::commands::service::check_started(home, &crate::commands::service::APPROVALS)
}

/// The lock on `store`'s listener, held while the returned file is open.
/// `None` when another listener holds it.
fn try_lock(store: &Store) -> Result<Option<File>> {
    lock_at(&store.dir().join("listen.lock"))
}

/// [`try_lock`] on `path`. The file is opened (made, owner-only, when
/// missing) in place, never written to a temporary name and renamed: two
/// first starts would each lock their own file then, and both run.
fn lock_at(path: &std::path::Path) -> Result<Option<File>> {
    if let Some(parent) = path.parent() {
        crate::home::create_private_dir(parent)?;
    }
    let file = crate::home::private_lock_options()
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", path.display()))
        }
    }
}

/// A line of the listener's output, with the time.
fn say(line: &str) {
    eprintln!("{} {line}", crate::time::clock(crate::time::now_ms()));
}

/// `openmoat approvals listen [--service]`.
pub fn listen(args: &ListenArgs) -> Result<Code> {
    if args.service {
        let home = Home::locate()?;
        home.require_exists()?;
        service_launch(&home)?;
    } else {
        person(COMMAND)?;
    }
    let (home, store) = store()?;
    deny_inspection();
    let mut waiting = false;
    let _lock = loop {
        match try_lock(&store)? {
            Some(lock) => break lock,
            None if args.service => {
                if !waiting {
                    say("another `openmoat approvals listen` is running; waiting for it to stop");
                    waiting = true;
                }
                std::thread::sleep(IDLE);
            }
            None => bail!(
                "another `openmoat approvals listen` is running for this state directory \
                 (the service, if `openmoat approvals install` set it up)"
            ),
        }
    };
    // Ctrl-C (`SIGINT`), and the service manager's stop (`SIGTERM`), end the
    // listener cleanly: both halves stop and the beat is removed (ADR-093).
    let interrupted = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(&interrupted))
            .context("stopping on Ctrl-C")?;
    }
    let mut last = String::new();
    loop {
        let stopped = match run(&home, &store, args.service, &interrupted) {
            Ok(()) => {
                say("stopped; requests now wait unanswered and expire");
                return Ok(Code::Ok);
            }
            Err(stopped) => stopped,
        };
        if !args.service {
            return Err(stopped);
        }
        // The service waits for a channel rather than exiting into restarts.
        let line = format!("{stopped:#}; looking again every {} s", IDLE.as_secs());
        if line != last {
            say(&line);
            last = line;
        }
        if pause(IDLE, &interrupted) {
            return Ok(Code::Ok);
        }
    }
}

/// Sleep `span`, or less once interrupted; whether it was.
fn pause(span: Duration, interrupted: &AtomicBool) -> bool {
    let until = std::time::Instant::now() + span;
    while !interrupted.load(Ordering::Relaxed) {
        let left = until.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        std::thread::sleep(left.min(Duration::from_millis(200)));
    }
    true
}

/// The settings as a person left them, refused once another channel than
/// `spec` is connected or none is.
fn refresh(store: &Store, spec: &Spec) -> Result<Settings> {
    let (_, settings) = connected(store)?;
    if settings.channel != spec.name {
        bail!("another channel was connected; run `listen` again");
    }
    Ok(settings)
}

/// Listen on the connected channel until interrupted (`Ok`) or until it
/// changes or goes away (`Err`). Two halves (ADR-093,
/// [`crate::remote::listen::run`]): this thread sends requests as they appear
/// and keeps the beat; another long-polls the channel for answers, with a
/// channel of its own. A poll still in flight when this returns is dropped,
/// unconfirmed, so its replies come again.
fn run(home: &Home, store: &Store, service: bool, interrupted: &Arc<AtomicBool>) -> Result<()> {
    let (key, settings) = connected(store)?;
    // Answers a listener that stopped mid-answer staged and never placed.
    store.sweep_unplaced();
    let (spec, mut sender) = crate::remote::open(store, &REGISTRY, &key, &settings)?;
    let (_, poller) = crate::remote::open(store, &REGISTRY, &key, &settings)?;
    let shared = Arc::new(Shared::new(Arc::clone(interrupted)));
    if service {
        say(&format!(
            "listening for answers over {} as the service",
            spec.title
        ));
    } else {
        eprintln!(
            "listening for answers over {}; Ctrl-C stops (requests then wait unanswered and \
             expire)",
            spec.title
        );
    }
    {
        let (home, store, settings, shared) = (
            home.clone(),
            store.clone(),
            settings.clone(),
            Arc::clone(&shared),
        );
        let mut poller = poller;
        // Detached: it may be waiting on the channel's server when this
        // returns, and nothing it holds needs more than its own end.
        std::thread::spawn(move || {
            let key = match Key::load(&store.key_path()) {
                Ok(key) => key,
                Err(error) => {
                    say(&format!("cannot take answers: {error:#}"));
                    shared.halt();
                    return;
                }
            };
            let mut records = AuditRecords { home: &home };
            let mut listener = Listener::new(&store, &key, spec, settings);
            run::answering(
                &mut listener,
                (poller.as_mut(), &mut records),
                &shared,
                &|| refresh(&store, spec),
                &say,
            );
        });
    }
    let mut records = AuditRecords { home };
    let mut listener = Listener::new(store, &key, spec, settings);
    run::sending(
        &mut listener,
        (sender.as_mut(), &mut records),
        &shared,
        &|| refresh(store, spec),
        &say,
    )
    .context("stopped")?;
    if shared.interrupted() {
        Ok(())
    } else {
        bail!("stopped: the half that takes answers ended")
    }
}

/// The listener holds the channel's credential and the approval key: on
/// Linux it is made non-dumpable, so another process of the same user cannot
/// attach to it or read its memory through `/proc` (as `ptrace_scope` 0
/// allows). A failure leaves it as it was; it is hardening, not the boundary.
#[cfg(target_os = "linux")]
fn deny_inspection() {
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};
    if let Err(error) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        eprintln!("moat: could not make the listener non-dumpable: {error}");
    }
}

/// Elsewhere there is no such switch without `unsafe`; on macOS another
/// process gets the listener's task port only with a debugger's authorization.
#[cfg(not(target_os = "linux"))]
fn deny_inspection() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Of two first starts, one holds the lock and the other is refused:
    /// both open the same file, made in place.
    #[test]
    fn two_first_starts_get_one_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remote").join("listen.lock");
        let (first, second) = std::thread::scope(|scope| {
            let a = scope.spawn(|| lock_at(&path).unwrap());
            let b = scope.spawn(|| lock_at(&path).unwrap());
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_eq!(
            usize::from(first.is_some()) + usize::from(second.is_some()),
            1,
            "exactly one lock"
        );
        drop((first, second));
        assert!(lock_at(&path).unwrap().is_some(), "free again once closed");
    }

    #[test]
    fn variables_that_steer_tls_or_the_loader_are_named() {
        let names = [
            "PATH",
            "HOME",
            "SSL_CERT_FILE",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "MOAT_HOME",
            "XPC_SERVICE_NAME",
            "SSL_CERT_DIR",
        ]
        .map(OsString::from);
        assert_eq!(
            steering(names.into_iter()),
            [
                "DYLD_INSERT_LIBRARIES",
                "LD_PRELOAD",
                "SSL_CERT_DIR",
                "SSL_CERT_FILE"
            ]
        );
        let clean = ["PATH", "HOME", "MOAT_HOME", "TMPDIR"].map(OsString::from);
        assert_eq!(steering(clean.into_iter()), Vec::<String>::new());
    }
}

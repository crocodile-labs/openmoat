//! Renewing `command` sources while the proxy runs (ADR-087), each secret on
//! a thread of its own: no request waits for a program, a slow program does
//! not hold up another secret's renewal, and no request gets a value past
//! its deadline (the broker refuses it, `proxy-secret-expired`).
//!
//! A value is renewed a lead time before its deadline, counted from the
//! lifetime it actually got (the shorter of `lifetime` and the expiry the
//! program printed), and a program that answered is not run again within a
//! minute. Each renewed value is added to what the audit log masks. A failed
//! run is said on standard error, naming the secret and the reason, never
//! output; it is tried again after [`RETRY`].

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Result;
use openmoat_audit::KnownSecrets;
use openmoat_proxy::Rotation;
use zeroize::Zeroizing;

use super::command::Program;

/// How long after a failed run the program is run again.
const RETRY: Duration = Duration::from_secs(15);
/// How often a thread looks at its deadline. Short, because a machine's
/// sleep may not count on the clock a thread sleeps by.
const TICK: Duration = Duration::from_secs(2);
/// The least time between two runs of one program that answered.
const MIN_INTERVAL: Duration = Duration::from_secs(60);
/// How many values of each secret the audit log keeps masking.
const MASKED: usize = 5;

/// The masks the audit writer takes up at its next row.
pub type Masks = Arc<Mutex<Option<KnownSecrets>>>;

/// Every value the audit log masks: the fixed ones, and each renewed
/// secret's last few, the newest first.
struct Values {
    fixed: Vec<Zeroizing<String>>,
    renewed: Vec<Vec<Zeroizing<String>>>,
}

impl Values {
    fn known(&self) -> Result<KnownSecrets> {
        let values = self.fixed.iter().chain(self.renewed.iter().flatten());
        Ok(KnownSecrets::new(values.map(|v| v.as_str()))?)
    }
}

/// What the renewing threads share.
struct Shared {
    values: Mutex<Values>,
    masks: Masks,
}

struct Renewed {
    program: Program,
    rotation: Rotation,
    /// Its values' place in [`Values::renewed`].
    slot: usize,
    /// When the current value was given, and for how long.
    given: Instant,
    lifetime: Duration,
    last_run: Option<Instant>,
    next_try: Instant,
}

/// The `command` sources of one proxy and the values the audit log masks.
pub struct Refresher {
    renewed: Vec<Renewed>,
    shared: Arc<Shared>,
}

/// Names the secrets it renews, never a value.
impl std::fmt::Debug for Refresher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.renewed.iter().map(|r| r.program.id()))
            .finish()
    }
}

impl Refresher {
    /// Renew `programs`, each with the broker handle of its secret and the
    /// value it gave at start; `fixed` are the values of the other sources.
    pub fn new(
        programs: Vec<(Program, Rotation, Zeroizing<String>)>,
        fixed: Vec<Zeroizing<String>>,
    ) -> Self {
        let now = Instant::now();
        let mut values = Values {
            fixed,
            renewed: Vec::with_capacity(programs.len()),
        };
        let renewed = programs
            .into_iter()
            .enumerate()
            .map(|(slot, (program, rotation, value))| {
                values.renewed.push(vec![value]);
                Renewed {
                    lifetime: rotation.remaining().unwrap_or(Duration::ZERO),
                    program,
                    rotation,
                    slot,
                    given: now,
                    last_run: None,
                    next_try: now,
                }
            })
            .collect();
        Self {
            renewed,
            shared: Arc::new(Shared {
                values: Mutex::new(values),
                masks: Arc::new(Mutex::new(None)),
            }),
        }
    }

    /// Every value the audit log masks now.
    pub fn known(&self) -> Result<KnownSecrets> {
        lock(&self.shared.values).known()
    }

    /// Where renewed masks are put for the audit writer.
    pub fn masks(&self) -> Masks {
        Arc::clone(&self.shared.masks)
    }

    /// Renew in the background for as long as the process runs, one thread
    /// per secret. Nothing to renew starts no thread.
    pub fn spawn(self) {
        for mut renewed in self.renewed {
            let shared = Arc::clone(&self.shared);
            std::thread::spawn(move || {
                loop {
                    if let Some(line) = renewed.step(Instant::now(), &shared) {
                        eprintln!("{line}");
                    }
                    std::thread::sleep(TICK);
                }
            });
        }
    }

    /// One look at every secret, in turn; the lines to report.
    #[cfg(all(test, unix))]
    fn tick(&mut self, now: Instant) -> Vec<String> {
        let shared = Arc::clone(&self.shared);
        self.renewed
            .iter_mut()
            .filter_map(|r| r.step(now, &shared))
            .collect()
    }
}

impl Renewed {
    /// How long before the deadline the value is renewed: `refresh_before`,
    /// or a fifth of the lifetime the value got when that is shorter, but
    /// at least twice the program's time limit.
    fn lead(&self) -> Duration {
        self.program
            .refresh_before()
            .min(self.lifetime / 5)
            .max(self.program.time_limit() * 2)
    }

    /// Whether the program is run now: within the lead of the deadline (on
    /// the monotonic clock, or on the broker's, which counts a machine's
    /// sleep), past any retry time, and a minute after its last answer.
    fn due(&self, now: Instant) -> bool {
        let lead = self.lead();
        let by_clock = now + lead >= self.given + self.lifetime;
        let by_broker = self.rotation.remaining().unwrap_or(Duration::ZERO) <= lead;
        (by_clock || by_broker)
            && now >= self.next_try
            && self.last_run.is_none_or(|last| now >= last + MIN_INTERVAL)
    }

    /// Run the program when due and use its answer; a line to report.
    fn step(&mut self, now: Instant, shared: &Shared) -> Option<String> {
        if !self.due(now) {
            return None;
        }
        let answer = match self.program.fetch() {
            Ok(answer) => answer,
            Err(error) => return Some(self.failed(now, &error)),
        };
        // A failure is retried after [`RETRY`]; an answer, whatever it says,
        // is not asked for again within [`MIN_INTERVAL`].
        self.last_run = Some(now);
        // The audit log masks a value before any request can carry it.
        {
            let mut values = lock(&shared.values);
            let mine = &mut values.renewed[self.slot];
            if !mine.contains(&answer.value) {
                mine.insert(0, answer.value.clone());
                mine.truncate(MASKED);
            }
            match values.known() {
                Ok(known) => *lock(&shared.masks) = Some(known),
                Err(error) => {
                    return Some(format!(
                        "openmoat proxy: renewed values are not used: {error:#}"
                    ));
                }
            }
        }
        let lifetime = answer.lifetime;
        match self.rotation.renew(answer.value, lifetime) {
            Ok(()) => {
                self.given = now;
                self.lifetime = lifetime;
                None
            }
            Err(error) => Some(self.failed(now, &error.into())),
        }
    }

    fn failed(&mut self, now: Instant, error: &anyhow::Error) -> String {
        self.next_try = now + RETRY;
        failed(self.program.id(), error)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn failed(id: &str, error: &anyhow::Error) -> String {
    format!(
        "openmoat proxy: secret `{id}` was not renewed: {error:#}; requests that need it are \
         refused once it expires"
    )
}

#[cfg(all(test, unix))]
mod tests;

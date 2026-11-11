//! Renewing `command` sources while the proxy runs (ADR-087), on a thread of
//! its own: no request waits for a program, and none gets a value past its
//! deadline (the broker refuses it, `proxy-secret-expired`).
//!
//! Each renewed value is added to what the audit log masks. A failed run is
//! said on standard error, naming the secret and the reason, never output;
//! it is tried again every [`RETRY`] until it succeeds.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Result;
use openmoat_audit::KnownSecrets;
use openmoat_proxy::Rotation;
use zeroize::Zeroizing;

use super::command::Program;

/// How long after a failed run the program is run again.
const RETRY: Duration = Duration::from_secs(15);
/// How often the thread looks at the deadlines. Short, because a machine's
/// sleep may not count on the clock a thread sleeps by.
const TICK: Duration = Duration::from_secs(2);
/// How many values of each secret the audit log keeps masking.
const MASKED: usize = 5;

/// The masks the audit writer takes up at its next row.
pub type Masks = Arc<Mutex<Option<KnownSecrets>>>;

struct Renewed {
    program: Program,
    rotation: Rotation,
    /// The newest first.
    values: Vec<Zeroizing<String>>,
    next_try: Instant,
}

/// The `command` sources of one proxy and the values the audit log masks.
pub struct Refresher {
    renewed: Vec<Renewed>,
    fixed: Vec<Zeroizing<String>>,
    masks: Masks,
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
        Self {
            renewed: programs
                .into_iter()
                .map(|(program, rotation, value)| Renewed {
                    program,
                    rotation,
                    values: vec![value],
                    next_try: now,
                })
                .collect(),
            fixed,
            masks: Arc::new(Mutex::new(None)),
        }
    }

    /// Every value the audit log masks now.
    pub fn known(&self) -> Result<KnownSecrets> {
        let values = self
            .fixed
            .iter()
            .chain(self.renewed.iter().flat_map(|r| &r.values));
        Ok(KnownSecrets::new(values.map(|v| v.as_str()))?)
    }

    /// Where renewed masks are put for the audit writer.
    pub fn masks(&self) -> Masks {
        Arc::clone(&self.masks)
    }

    /// Renew in the background for as long as the process runs. Nothing to
    /// renew starts no thread.
    pub fn spawn(mut self) {
        if self.renewed.is_empty() {
            return;
        }
        std::thread::spawn(move || {
            loop {
                for line in self.tick(Instant::now()) {
                    eprintln!("{line}");
                }
                std::thread::sleep(TICK);
            }
        });
    }

    /// Run each program whose value is within its `refresh_before` of the
    /// deadline, or past it; the lines to report.
    fn tick(&mut self, now: Instant) -> Vec<String> {
        let mut lines = Vec::new();
        let mut answers = Vec::new();
        for (i, r) in self.renewed.iter_mut().enumerate() {
            let left = r.rotation.remaining().unwrap_or(Duration::ZERO);
            if left > r.program.refresh_before() || now < r.next_try {
                continue;
            }
            match r.program.fetch() {
                Ok(answer) => {
                    if !r.values.contains(&answer.value) {
                        r.values.insert(0, answer.value.clone());
                        r.values.truncate(MASKED);
                    }
                    answers.push((i, answer));
                }
                Err(error) => {
                    r.next_try = now + RETRY;
                    lines.push(failed(r.program.id(), &error));
                }
            }
        }
        if answers.is_empty() {
            return lines;
        }
        // The audit log masks a value before any request can carry it.
        match self.known() {
            Ok(known) => *self.masks.lock().unwrap_or_else(PoisonError::into_inner) = Some(known),
            Err(error) => {
                lines.push(format!(
                    "openmoat proxy: renewed values are not used: {error:#}"
                ));
                return lines;
            }
        }
        for (i, answer) in answers {
            let r = &mut self.renewed[i];
            if let Err(error) = r.rotation.renew(answer.value, answer.lifetime) {
                r.next_try = now + RETRY;
                lines.push(failed(r.program.id(), &error.into()));
            }
        }
        lines
    }
}

fn failed(id: &str, error: &anyhow::Error) -> String {
    format!(
        "openmoat proxy: secret `{id}` was not renewed: {error:#}; requests that need it are \
         refused once it expires"
    )
}

#[cfg(all(test, unix))]
mod tests;

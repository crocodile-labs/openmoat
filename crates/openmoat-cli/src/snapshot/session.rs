//! The snapshots `openmoat run` takes: one before the agent starts and one
//! after it exits, in its own process outside the sandbox (ADR-085 §3).
//!
//! A snapshot that cannot be taken is said on stderr and the run goes on:
//! snapshots put files back after the fact, they do not decide what the agent
//! may do. A run started from an agent takes none, so an agent cannot fill
//! the store and push a person's snapshots out of it.

use anyhow::Result;
use openmoat_core::EvalContext;

use super::capture::Denied;
use super::{Limits, Reason, Retention, Store, Taken};
use crate::home::Home;

/// The deny rules a snapshot of the project leaves out: the person's policy,
/// OpenMoat's own binary, and the repository policy's deny rules.
pub fn denied(home: &Home, ctx: &EvalContext) -> Result<Denied> {
    let mut user = home.load_policy()?;
    crate::install::self_paths::protect_recorded(home, &mut user)?;
    let policy = crate::repo::with_repo_denies(home, ctx, user)?;
    Denied::new(policy, ctx)
}

/// The snapshots of one `openmoat run`.
pub struct RunSnapshots {
    taking: Option<(Store, Denied)>,
    home: Home,
    session: String,
}

impl RunSnapshots {
    /// Take the snapshot before the agent starts, after removing what the
    /// store's retention does not keep; `off` is `--no-snapshot`, recorded.
    pub fn start(home: &Home, ctx: &EvalContext, off: bool, session: &str) -> Self {
        let mut run = Self {
            taking: None,
            home: home.clone(),
            session: session.to_owned(),
        };
        if off {
            eprintln!("openmoat run: no snapshot of the project (--no-snapshot)");
            super::record(
                home,
                session,
                "snapshot",
                "snapshot-off",
                "`openmoat run --no-snapshot`: no snapshot of the project".to_owned(),
            );
            return run;
        }
        if let Err(error) = crate::terminal::refuse_agent("openmoat run") {
            eprintln!("openmoat run: no snapshot of the project: {error:#}");
            return run;
        }
        let opened = (|| -> Result<(Store, Denied)> {
            let project = ctx.project.as_deref().unwrap_or(&ctx.cwd);
            let store = Store::open(home, std::path::Path::new(project))?;
            let denied = denied(home, ctx)?;
            store.prune(Retention::default(), crate::time::now_ms())?;
            Ok((store, denied))
        })();
        match opened {
            Ok(taking) => {
                run.taking = Some(taking);
                run.take(Reason::RunStart);
            }
            Err(error) => eprintln!("openmoat run: no snapshot of the project: {error:#}"),
        }
        run
    }

    /// Take the snapshot after the agent exited.
    pub fn finish(self) {
        self.take(Reason::RunExit);
    }

    fn take(&self, reason: Reason) {
        let Some((store, denied)) = &self.taking else {
            return;
        };
        let started = std::time::Instant::now();
        match store.take(denied, Limits::default(), reason, Some(&self.session)) {
            Ok(taken) => {
                let line = said(&taken, reason, started.elapsed().as_millis());
                eprintln!("openmoat run: {line}");
                super::record(&self.home, &self.session, "snapshot", "snapshot", line);
            }
            Err(error) => {
                let line = format!("no snapshot {}: {error:#}", reason.words());
                eprintln!("openmoat run: {line}");
                super::record(
                    &self.home,
                    &self.session,
                    "snapshot",
                    "snapshot-failed",
                    line,
                );
            }
        }
    }
}

/// One line on a snapshot taken.
pub fn said(taken: &Taken, reason: Reason, ms: u128) -> String {
    let s = taken.snapshot();
    let left_out = match s.meta.left_out_total {
        0 => String::new(),
        n => format!(", {n} left out (`openmoat snapshot --list` names them)"),
    };
    match taken {
        Taken::New(_) => format!(
            "snapshot {} {}: {} files{left_out}, in {ms} ms; `openmoat restore {}` puts them back",
            s.id,
            reason.words(),
            s.meta.files,
            s.id
        ),
        Taken::Unchanged(_) => format!(
            "no change {} since snapshot {} ({})",
            reason.words(),
            s.id,
            s.meta.reason.words()
        ),
    }
}

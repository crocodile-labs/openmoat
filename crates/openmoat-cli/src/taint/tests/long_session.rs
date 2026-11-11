//! A long session under the default policy, as an agent makes one: shell
//! commands, file reads and writes, in more than one directory of a project.

use std::time::{Duration, Instant};

use openmoat_audit::{NewEvent, Store};
use openmoat_core::{Action, CompiledPolicy, Decision, EvalContext, Policy, Verdict};
use openmoat_hosts::Host;

use super::super::{CacheWrite, Progress, SessionTaint, of_session};

/// The `i`th call of a session working in `cwd`.
fn nth(i: usize, cwd: &str) -> Action {
    match i % 8 {
        0 => Action::Shell {
            command: format!("cd {cwd} && cargo test -p crate{} 2>&1 | tail -20", i % 13),
        },
        1 => Action::Shell {
            command: format!("grep -rn 'fn item{i}' src | head -5"),
        },
        2 => Action::Shell {
            command: "git status --short".to_owned(),
        },
        3 => Action::FsWrite {
            path: format!("{cwd}/src/m{}.rs", i % 97),
        },
        4 => Action::Shell {
            command: format!("ls -la {cwd}/src/dir{} && wc -l src/m1.rs", i % 31),
        },
        _ => Action::FsRead {
            path: format!("{cwd}/src/file{i}.rs"),
        },
    }
}

/// A project below a home directory, both under a temporary directory, and
/// the default policy.
struct Session {
    _dir: tempfile::TempDir,
    home: String,
    project: String,
    store: Store,
    policy: Policy,
}

impl Session {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::context::path_string(&dir.path().canonicalize().unwrap());
        let home = format!("{root}/home");
        let project = format!("{home}/proj");
        Self {
            _dir: dir,
            home,
            project,
            store: Store::open_in_memory().unwrap(),
            policy: Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap(),
        }
    }

    fn record(&self, cwd: &str, action: &Action) {
        let decision = Decision::new(Verdict::Allow);
        self.store
            .record(&NewEvent {
                host: Host::ClaudeCode.id(),
                session_id: "s1",
                call_id: None,
                cwd: Some(cwd),
                tool: "tool",
                action: Some(action),
                decision: &decision,
                latency_us: 0,
            })
            .unwrap();
    }

    /// The guard's taint lookup for a call in `cwd`, writing the cache as the
    /// guard does: what it folded to and how many events it classified.
    fn call(&self, cwd: &str, deadline: Instant) -> anyhow::Result<(SessionTaint, usize)> {
        let ctx = EvalContext {
            home: self.home.clone(),
            project: Some(self.project.clone()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: cwd.to_owned(),
            case_insensitive_paths: false,
        };
        let compiled = CompiledPolicy::compile(&self.policy, &ctx).unwrap();
        let mut save = |write: &CacheWrite| write.write(&self.store);
        let mut progress = Progress {
            deadline,
            save: &mut save,
            folded: 0,
        };
        let (taint, write) = of_session(
            &self.store,
            Host::ClaudeCode,
            "s1",
            &compiled,
            cwd,
            &mut progress,
        )?;
        if let Some(write) = write {
            write.write(&self.store);
        }
        Ok((taint, progress.folded))
    }
}

/// 50,000 calls in a project, then the agent moves to a folder of it: the
/// first call there is decided well within the guard's taint budget, folding
/// only the call recorded since, where before it folded all 50,000 again and
/// ran out of time on every call.
#[test]
fn a_directory_change_late_in_a_long_session_is_decided_within_the_budget() {
    const EVENTS: usize = 50_000;
    // An agent repeats itself; 2,000 distinct calls among the 50,000.
    const DISTINCT: usize = 2_000;
    let session = Session::new();
    let here = session.project.clone();
    for i in 0..EVENTS {
        session.record(&here, &nth(i % DISTINCT, &here));
    }
    let started = Instant::now();
    let (_, folded) = session
        .call(&here, Instant::now() + Duration::from_hours(1))
        .unwrap();
    let full = started.elapsed();
    assert_eq!(folded, EVENTS);
    eprintln!("a fold of {EVENTS} calls ({DISTINCT} distinct) from the first: {full:?}");

    let sub = format!("{here}/sub");
    session.record(&sub, &nth(7, &sub));
    let started = Instant::now();
    let budget = crate::commands::guard::TAINT_BUDGET;
    let (taint, folded) = session.call(&sub, started + budget).unwrap();
    let first = started.elapsed();
    eprintln!("the first call in {sub}: {first:?}, {folded} call(s) folded");
    assert_eq!(folded, 1, "the call in the new directory read on");
    // Compiling the default policy is part of it; a loaded runner is slow.
    assert!(first < budget / 4, "{first:?}");
    assert!(!taint.cwdless);
}

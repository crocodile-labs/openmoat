//! An upgrade from each release before the audit key, with a long session in
//! the log, through the steps a guard call and the `PostToolUse` after it take,
//! in their order: the taint fold reads the old log read-only and saves part-way
//! (the first writer, #837), the call is recorded, the output is kept and the
//! fold read on. Each is decided and recorded, the key is made once, by the
//! first writer, and keyed events start after the old ones.

use std::time::{Duration, Instant};

use openmoat_audit::testing::{VERSIONS_BEFORE_THE_KEY, as_written_by};
use openmoat_core::{Action, CompiledPolicy, EvalContext, Policy};
use openmoat_hosts::Host;

use super::*;
use crate::taint::{self, CacheWrite, Progress};

/// The long session, and the calls recorded in it before the copies.
const SESSION: &str = "long";
const CALLS: usize = 16;
/// Copies of those calls in the older log: more than one page of the fold
/// (512 events), so it saves part-way.
const REPEAT: usize = 40;

fn shell(command: &str) -> Action {
    Action::Shell {
        command: command.to_owned(),
    }
}

fn record_in(store: &Store, session: &str, cwd: &str, action: &Action) {
    let decision = Decision::single(Verdict::Allow, "dev-shell", "ok");
    store
        .record(&NewEvent {
            host: Host::ClaudeCode.id(),
            session_id: session,
            call_id: None,
            cwd: Some(cwd),
            tool: "Bash",
            action: Some(action),
            decision: &decision,
            latency_us: 1,
        })
        .unwrap();
}

/// The default policy compiled for a call in `project`, below `user_home`.
fn compiled<'p>(policy: &'p Policy, user_home: &str, project: &str) -> CompiledPolicy<'p> {
    let ctx = EvalContext {
        home: user_home.to_owned(),
        project: Some(project.to_owned()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: project.to_owned(),
        case_insensitive_paths: false,
    };
    CompiledPolicy::compile(policy, &ctx).unwrap()
}

#[test]
fn a_long_session_after_an_upgrade_from_every_older_version_is_decided_and_recorded() {
    let policy = Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap();
    for version in VERSIONS_BEFORE_THE_KEY {
        let (dir, home) = home();
        let root = crate::context::path_string(&dir.path().canonicalize().unwrap());
        let (user_home, project) = (format!("{root}/user"), format!("{root}/user/proj"));
        // The log an older release left: its calls, then no key.
        open(&home).unwrap();
        let store = open_existing(&home).unwrap();
        for i in 0..CALLS {
            record_in(
                &store,
                SESSION,
                &project,
                &shell(&format!("cargo test -p c{i}")),
            );
            record_in(&store, "other", &project, &shell("git status"));
        }
        drop(store);
        as_written_by(&home.audit_path(), version, REPEAT).unwrap();
        std::fs::remove_file(path(&home)).unwrap();
        let old = i64::try_from(2 * CALLS * REPEAT).unwrap();
        let compiled = compiled(&policy, &user_home, &project);

        // PreToolUse: the guard reads the session read-only and folds it,
        // saving part-way through the key's module. That save is the first
        // writer: it upgrades the log and makes the key.
        let reader = home.open_audit().unwrap();
        let mut saves = 0;
        let mut save = |write: &CacheWrite| {
            write.save_in(&home);
            saves += 1;
        };
        let mut progress = Progress {
            deadline: Instant::now() + Duration::from_hours(1),
            save: &mut save,
            every: Duration::ZERO,
            folded: 0,
        };
        let (_, write) = taint::of_session(
            &reader,
            Host::ClaudeCode,
            SESSION,
            &compiled,
            &project,
            &mut progress,
        )
        .unwrap();
        assert!(progress.folded >= CALLS * REPEAT, "version {version}");
        drop(reader);
        assert!(saves > 0, "version {version}: the fold saved part-way");
        let key = std::fs::read(path(&home)).unwrap();
        assert_eq!(
            read(&home).unwrap().unwrap().after(),
            EventId(old),
            "version {version}: keyed events start after the old ones"
        );

        // The call is recorded, with the fold, on the guard's writable handle.
        let writable = open_existing(&home).unwrap();
        record_in(&writable, SESSION, &project, &shell("cargo build"));
        if let Some(write) = write {
            write.write(&writable);
        }
        drop(writable);

        // PostToolUse: the output is kept and the fold read on.
        let writable = open_existing(&home).unwrap();
        let deadline = Instant::now() + Duration::from_hours(1);
        taint::catch_up(
            &writable,
            Host::ClaudeCode,
            SESSION,
            &compiled,
            &project,
            deadline,
        );
        drop(writable);

        // The next call, and `doctor`'s and `audit verify`'s view of the log.
        record_in(
            &open_existing(&home).unwrap(),
            SESSION,
            &project,
            &shell("ls"),
        );
        assert_eq!(
            std::fs::read(path(&home)).unwrap(),
            key,
            "the key is made once"
        );
        assert!(!missing_over_events(&home), "version {version}");
        let chain = home.open_audit().unwrap().verify_chain().unwrap();
        assert_eq!(chain.broken, None, "version {version}");
        assert_eq!(
            (chain.events, chain.keyed, chain.keyed_after),
            (u64::try_from(old).unwrap() + 2, 2, Some(EventId(old))),
            "version {version}"
        );
    }
}

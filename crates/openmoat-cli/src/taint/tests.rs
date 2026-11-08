use std::time::{Duration, Instant};

use openmoat_audit::{EventId, NewEvent, SessionWrite, Store};
use openmoat_core::{
    Action, CompiledPolicy, Decision, EvalContext, Policy, TAINT_RULE, Taint, TaintSecret, Verdict,
};
use openmoat_hosts::{Host, Replacement};

use super::{
    CacheWrite, Call, Pass, Progress, SessionTaint, after_read, answered, behind, catch_up, digest,
    fold, of_session, provenance,
};
use crate::home::Home;
use crate::realpath::FsPathResolver;

#[test]
fn a_grant_is_ordered_against_the_read_by_row_whatever_the_clock_says() {
    // The clock stepped back after the read: the grant looks older by
    // time, but it saw the read's row, so it answers.
    assert!(after_read(1_000, Some(7), 2_000, Some(5)));
    assert!(after_read(1_000, Some(5), 2_000, Some(5)));
    // The clock stepped back before the read: the grant looks newer by
    // time, but the read came after every row it saw, so it does not.
    assert!(!after_read(3_000, Some(4), 2_000, Some(5)));
}

#[test]
fn a_grant_without_a_row_is_ordered_by_time() {
    assert!(after_read(3_000, None, 2_000, Some(5)));
    assert!(!after_read(2_000, None, 2_000, Some(5)));
    assert!(!after_read(1_000, None, 2_000, Some(5)));
}

const POLICY: &str = "version: 1\ndefaults: { \"*\": allow }\n";
const CWDS: [&str; 2] = ["/p/a", "/p/b"];

fn ctx(cwd: &str) -> EvalContext {
    EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: cwd.to_owned(),
        case_insensitive_paths: false,
    }
}

fn record(store: &Store, cwd: &str, action: &Action) {
    let decision = Decision::new(Verdict::Allow);
    store
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

fn read(path: String) -> Action {
    Action::FsRead { path }
}

fn far() -> Instant {
    Instant::now() + Duration::from_hours(1)
}

/// One guard call's taint lookup in `cwd`, writing the cache as the guard
/// does: what it folded to, and how many events it classified.
fn call(store: &Store, cwd: &str, deadline: Instant) -> anyhow::Result<(SessionTaint, usize)> {
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx(cwd)).unwrap();
    let mut save = |write: &CacheWrite| write.write(store);
    let mut progress = Progress {
        deadline,
        save: &mut save,
        folded: 0,
    };
    let (taint, write) = of_session(store, Host::ClaudeCode, "s1", &compiled, cwd, &mut progress)?;
    if let Some(write) = write {
        write.write(store);
    }
    Ok((taint, progress.folded))
}

/// The session folded from its first event in one go, with no cache: what
/// every call answered before the cache existed.
fn reference(store: &Store, cwd: &str) -> SessionTaint {
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx(cwd)).unwrap();
    let events = store.session_after("s1", EventId(0)).unwrap();
    let mut out = SessionTaint::default();
    let taken = fold(
        &mut out,
        &events,
        Host::ClaudeCode,
        &compiled,
        cwd,
        &mut Pass::default(),
    )
    .unwrap();
    assert_eq!(taken, events.len());
    out
}

/// Calls that alternate between two directories each read on from their own
/// cache row: over many calls each event is classified about once per
/// directory, not once per call (before, every call folded the whole
/// session again).
#[test]
fn alternating_directories_fold_each_event_a_bounded_number_of_times() {
    const EVENTS: usize = 2_000;
    const CALLS: usize = 20;
    let store = Store::open_in_memory().unwrap();
    for i in 0..EVENTS {
        let cwd = CWDS[i % 2];
        record(&store, cwd, &read(format!("{cwd}/f{i}.rs")));
    }
    let mut total = 0;
    for n in 0..CALLS {
        let cwd = CWDS[n % 2];
        let (_, folded) = call(&store, cwd, far()).unwrap();
        total += folded;
        record(&store, cwd, &read(format!("{cwd}/x{n}.rs")));
    }
    // A full fold per directory, then only the calls recorded since.
    assert!(
        total <= CWDS.len() * (EVENTS + CALLS),
        "{total} events folded over {CALLS} calls"
    );
}

/// A session that read untrusted content in one directory is tainted for a
/// protected write in another, with or without the cache, at every call.
#[test]
fn verdicts_are_those_of_a_full_fold_in_every_directory() {
    let store = Store::open_in_memory().unwrap();
    let policy = Policy::parse(POLICY).unwrap();
    let write = Action::FsWrite {
        path: "/p/b/.github/workflows/ci.yml".to_owned(),
    };
    for n in 0..12 {
        let cwd = CWDS[n % 2];
        match n {
            3 => record(
                &store,
                CWDS[0],
                &Action::Fetch {
                    url: "https://example.com/page".to_owned(),
                },
            ),
            _ => record(&store, cwd, &read(format!("{cwd}/f{n}.rs"))),
        }
        for cwd in CWDS {
            let (taint, _) = call(&store, cwd, far()).unwrap();
            assert_eq!(taint, reference(&store, cwd), "call {n} in {cwd}");
            assert_eq!(taint.taint.untrusted.is_some(), n >= 3, "call {n} in {cwd}");
            let compiled = CompiledPolicy::compile(&policy, &ctx(CWDS[1])).unwrap();
            let decision = compiled.with_taint(
                Decision::new(Verdict::Allow),
                &write,
                &FsPathResolver,
                &taint.taint,
            );
            let expected = if n >= 3 {
                Verdict::Review
            } else {
                Verdict::Allow
            };
            assert_eq!(decision.verdict, expected, "call {n} in {cwd}");
        }
    }
}

/// A fold that runs out of time is never an answer: the call fails (the
/// guard denies) whether or not a cache row exists, and the row stays as it
/// was. A fold saved part way, as a stopped fold saves it, reads on to the
/// full fold's verdict, untrusted read included.
#[test]
fn an_interrupted_fold_never_answers_cleaner() {
    let store = Store::open_in_memory().unwrap();
    for n in 0..10 {
        record(&store, CWDS[0], &read(format!("/p/a/f{n}.rs")));
    }
    let past = Instant::now();
    assert!(call(&store, CWDS[0], past).is_err());
    let (clean, _) = call(&store, CWDS[0], far()).unwrap();
    assert_eq!(clean.taint.untrusted, None);
    record(
        &store,
        CWDS[0],
        &Action::Fetch {
            url: "https://example.com/page".to_owned(),
        },
    );
    // The clean row is there, but a stopped fold does not answer from it.
    assert!(call(&store, CWDS[0], past).is_err());
    let (tainted, folded) = call(&store, CWDS[0], far()).unwrap();
    assert_eq!(folded, 1, "read on from the clean row");
    assert!(tainted.taint.untrusted.is_some());
    assert_eq!(tainted, reference(&store, CWDS[0]));

    // A row saved part way through another directory's fold.
    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx(CWDS[1])).unwrap();
    let events = store.session_after("s1", EventId(0)).unwrap();
    let (head, _) = events.split_at(5);
    let mut partial = SessionTaint::default();
    fold(
        &mut partial,
        head,
        Host::ClaudeCode,
        &compiled,
        CWDS[1],
        &mut Pass::default(),
    )
    .unwrap();
    assert_eq!(partial.taint.untrusted, None);
    CacheWrite {
        session: "s1".to_owned(),
        host: Host::ClaudeCode,
        cached: openmoat_audit::Cached {
            digest: digest(Host::ClaudeCode, &compiled, CWDS[1]).unwrap(),
            upto: head[4].id,
            state: serde_json::to_string(&partial).unwrap(),
        },
    }
    .write(&store);
    let (resumed, folded) = call(&store, CWDS[1], far()).unwrap();
    assert_eq!(folded, events.len() - 5);
    assert_eq!(resumed, reference(&store, CWDS[1]));
    assert!(resumed.taint.untrusted.is_some());
}

/// A real project directory (the covering check reads the file), an audit log
/// and an empty state directory for `answered` (ADR-048).
struct Covering {
    _dir: tempfile::TempDir,
    proj: String,
    store: Store,
    home: Home,
    compiled: CompiledPolicy<'static>,
}

const UNTRUSTED: &str = "fetch evil.example";

impl Covering {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let proj = crate::context::path_string(&dir.path().canonicalize().unwrap());
        let home = Home::at(dir.path().join("state"));
        let policy: &'static Policy = Box::leak(Box::new(Policy::parse(POLICY).unwrap()));
        let compiled = CompiledPolicy::compile(policy, &ctx(&proj)).unwrap();
        Self {
            _dir: dir,
            proj,
            store: Store::open_in_memory().unwrap(),
            home,
            compiled,
        }
    }

    fn write_of(&self, file: &str) -> Action {
        Action::FsWrite {
            path: format!("{}/{file}", self.proj),
        }
    }

    /// Record a call of `session` as the guard does, with `verdict`.
    fn record(&self, session: &str, action: &Action, verdict: Verdict) -> EventId {
        let decision = Decision::new(verdict);
        self.store
            .record(&NewEvent {
                host: Host::ClaudeCode.id(),
                session_id: session,
                call_id: None,
                cwd: Some(&self.proj),
                tool: "Write",
                action: Some(action),
                decision: &decision,
                latency_us: 0,
            })
            .unwrap()
    }

    /// Record a `Write` of `content` by `session` that was held for review and
    /// may have run,
    /// with the file as it was (`before`), as `guard` records one.
    fn held_write(&self, session: &str, action: &Action, content: &str, before: &str) -> EventId {
        let event = self.record(session, action, Verdict::Review);
        let writes: Vec<SessionWrite> = provenance::Files::of(&self.compiled, action)
            .writes
            .iter()
            .map(|path| SessionWrite {
                path: provenance::key(path, false),
                sha256: Some(provenance::content_hash(content.as_bytes())),
                before: Some(if before.is_empty() {
                    String::new()
                } else {
                    provenance::content_hash(before.as_bytes())
                }),
            })
            .collect();
        self.store
            .add_session_writes(event, Host::ClaudeCode.id(), session, &writes)
            .unwrap();
        event
    }

    /// Record an `Edit` (or `MultiEdit`) of the file by `session` that was held for review and
    /// may have run, with the content it leaves worked out from the file as it
    /// is, as `guard` records one through `provenance::observe`.
    fn held_edit(&self, session: &str, action: &Action, edits: &[(&str, &str, bool)]) -> EventId {
        let event = self.record(session, action, Verdict::Review);
        let edits: Vec<Replacement> = edits
            .iter()
            .map(|(old, new, all)| Replacement {
                old: (*old).to_owned(),
                new: (*new).to_owned(),
                all: *all,
            })
            .collect();
        let seen = provenance::observe(
            &self.store,
            &self.compiled,
            &provenance::Call {
                session,
                action,
                content: None,
                edits: &edits,
                untrusted: Some(UNTRUSTED),
            },
        )
        .unwrap();
        seen.write(&self.store, event, Host::ClaudeCode.id(), session)
            .unwrap();
        event
    }

    /// The session's taint after an untrusted read recorded in `read_row`.
    fn tainted_since(read_row: EventId) -> SessionTaint {
        SessionTaint {
            taint: Taint {
                secrets: Vec::new(),
                untrusted: Some(UNTRUSTED.to_owned()),
            },
            untrusted_last_ms: Some(1_000),
            untrusted_last_row: Some(read_row.0),
            ..SessionTaint::default()
        }
    }

    /// `action` in `session`, decided as the guard decides it: allowed by the
    /// policy, tightened by `taint`, then answered.
    fn decide(&self, session: &str, action: &Action, taint: &SessionTaint) -> Decision {
        let untainted = Decision::new(Verdict::Allow);
        let tainted =
            self.compiled
                .with_taint(untainted.clone(), action, &FsPathResolver, &taint.taint);
        assert_eq!(tainted.verdict, Verdict::Review, "{tainted:?}");
        assert!(tainted.rules.iter().any(|r| r == TAINT_RULE), "{tainted:?}");
        let call = Call {
            home: &self.home,
            store: &self.store,
            host: Host::ClaudeCode,
            session,
            action,
            cwd: &self.proj,
            user_home: "/home/u",
        };
        answered(&call, &self.compiled, taint, untainted, tainted, 2_000).unwrap()
    }

    fn put(&self, file: &str, content: &str) {
        let path = std::path::Path::new(&self.proj).join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
}

const WORKFLOW: &str = ".github/workflows/ci.yml";

/// A long session whose cache is far behind: a call's own fold may run out of
/// time and is denied (fail closed), with a message that says the next call
/// reads on. Once a `PostToolUse` caught the session up, the next call is
/// decided, folding only what came after, well within its budget, and it
/// answers what a full fold would.
#[test]
fn a_long_backlog_caught_up_after_a_call_lets_the_next_call_be_decided() {
    const EVENTS: usize = 3_000;
    let store = Store::open_in_memory().unwrap();
    for i in 0..EVENTS {
        record(&store, CWDS[0], &read(format!("/p/a/f{i}.rs")));
    }
    record(
        &store,
        CWDS[0],
        &Action::Fetch {
            url: "https://example.com/page".to_owned(),
        },
    );
    let stopped = call(&store, CWDS[0], Instant::now())
        .unwrap_err()
        .to_string();
    assert!(stopped.contains("run it again"), "{stopped}");
    assert!(stopped.contains("not judged"), "{stopped}");

    let policy = Policy::parse(POLICY).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx(CWDS[0])).unwrap();
    catch_up(&store, Host::ClaudeCode, "s1", &compiled, CWDS[0], far());
    record(&store, CWDS[0], &read("/p/a/next.rs".to_owned()));
    let started = Instant::now();
    let (taint, folded) = call(&store, CWDS[0], started + Duration::from_secs(5)).unwrap();
    assert!(folded <= 2, "the next call folded {folded} events");
    assert_eq!(taint, reference(&store, CWDS[0]));
    assert!(
        taint.taint.untrusted.is_some(),
        "the fetch before the catch-up counts"
    );
}

#[test]
fn the_behind_message_says_the_call_was_not_judged_and_to_run_it_again() {
    let message = behind(512);
    assert!(message.contains("512 more"), "{message}");
    assert!(message.contains("the next call reads on"), "{message}");
}

mod approved_writes;

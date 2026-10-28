use openmoat_audit::{EventId, NewEvent};
use openmoat_core::{EvalContext, Policy};

use super::*;
use crate::taint::provenance::{self, observe};

const POLICY: &str = "version: 1\ndefaults: { \"*\": allow }\n";

struct Fixture {
    _dir: tempfile::TempDir,
    proj: String,
    home: Home,
    store: Store,
    policy: Policy,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let proj = crate::context::path_string(&dir.path().canonicalize().unwrap());
    std::fs::create_dir_all(dir.path().join("state")).unwrap();
    let home = Home::at(dir.path().join("state"));
    let store = Store::open(&dir.path().join("audit.db")).unwrap();
    Fixture {
        _dir: dir,
        proj,
        home,
        store,
        policy: Policy::parse(POLICY).unwrap(),
    }
}

impl Fixture {
    fn compiled(&self) -> CompiledPolicy<'_> {
        let ctx = EvalContext {
            home: "/home/u".to_owned(),
            project: Some(self.proj.clone()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: self.proj.clone(),
            case_insensitive_paths: false,
        };
        CompiledPolicy::compile(&self.policy, &ctx).unwrap()
    }

    /// Record `action` of `session` on Gemini CLI as the guard does, with the
    /// files it writes; returns its event.
    fn ran(&self, session: &str, action: &Action, content: Option<&str>) -> EventId {
        let decision = Decision::new(Verdict::Allow);
        let id = self
            .store
            .record(&NewEvent {
                host: Host::GeminiCli.id(),
                session_id: session,
                call_id: None,
                cwd: None,
                tool: "t",
                action: Some(action),
                decision: &decision,
                latency_us: 0,
            })
            .unwrap();
        let call = provenance::Call {
            session,
            action,
            content,
            untrusted: None,
        };
        let seen = observe(&self.store, &self.compiled(), &call).unwrap();
        seen.write(&self.store, id, Host::GeminiCli.id(), session)
            .unwrap();
        id
    }

    fn write(&self, session: &str, file: &str) -> EventId {
        let path = format!("{}/{file}", self.proj);
        std::fs::write(&path, "print(1)\n").unwrap();
        self.ran(session, &Action::FsWrite { path }, Some("print(1)\n"))
    }

    /// The decision `session` gets for `command`, allowed by the policy.
    fn decide(&self, session: &str, command: &str, sandboxed: bool) -> Decision {
        self.decide_as(Host::GeminiCli, session, command, (sandboxed, false))
    }

    fn decide_as(
        &self,
        host: Host,
        session: &str,
        command: &str,
        (sandboxed, within_run): (bool, bool),
    ) -> Decision {
        let action = shell(command);
        let compiled = self.compiled();
        let call = provenance::Call {
            session,
            action: &action,
            content: None,
            untrusted: None,
        };
        let seen = observe(&self.store, &compiled, &call).unwrap();
        let code = Call {
            home: &self.home,
            host,
            session,
            action: &action,
            cwd: &self.proj,
            user_home: "/home/u",
            writes: &seen.written,
            within_run,
        };
        let allowed = Decision::single(Verdict::Allow, "dev-shell", "allowed");
        checked(
            &code,
            &compiled,
            &self.store,
            allowed,
            (crate::time::now_ms(), &|| sandboxed),
        )
        .unwrap()
    }

    fn grant(&self, session: &str, command: &str, seen_row: EventId) {
        let mut grants = Grants::load_in(&self.home).unwrap();
        let project = approvals::project_of(
            std::path::Path::new(&self.proj),
            std::path::Path::new("/home/u"),
        );
        let scope = approvals::Scope {
            host: Host::GeminiCli.id(),
            session_id: session,
            project: &project,
        };
        let asked = approvals::approvable(&shell(command), Some(&self.proj), "/home/u").unwrap();
        let now = crate::time::now_ms();
        grants.grant(scope, &asked, now, Some(seen_row.0));
        grants.save(&self.home.grants_path(), now).unwrap();
    }
}

fn shell(command: &str) -> Action {
    Action::Shell {
        command: command.to_owned(),
    }
}

fn asks(decision: &Decision) -> bool {
    decision.verdict == Verdict::Ask && decision.rules == [RULE]
}

#[test]
fn running_a_script_the_session_wrote_asks_where_no_sandbox_holds_it() {
    let f = fixture();
    f.write("a", "x.py");
    for command in [
        "python3 x.py",
        "python x.py",
        "python3 -u x.py",
        "env python3 x.py",
        "time python3 x.py",
        "bash -c 'python3 x.py'",
    ] {
        let decision = f.decide("a", command, false);
        assert!(asks(&decision), "{command}: {decision:?}");
        let reason = decision.reasons.join(" ");
        assert!(
            reason.contains("runs code this session wrote") && reason.contains("/x.py"),
            "{reason}"
        );
        // what allowed it is kept for the record
        assert!(
            decision.context.iter().any(|c| c == "allowed"),
            "{decision:?}"
        );
    }
}

#[test]
fn an_os_sandbox_or_openmoat_run_keeps_the_verdict() {
    let f = fixture();
    f.write("a", "x.py");
    assert_eq!(f.decide("a", "python3 x.py", true).verdict, Verdict::Allow);
    let inside = f.decide_as(Host::ClaudeCode, "a", "python3 x.py", (false, true));
    assert_eq!(inside.verdict, Verdict::Allow);
}

#[test]
fn files_the_session_did_not_write_keep_the_verdict() {
    let f = fixture();
    // there before the session, or written by another session or host
    std::fs::write(format!("{}/manage.py", f.proj), "x").unwrap();
    assert_eq!(
        f.decide("a", "python manage.py", false).verdict,
        Verdict::Allow
    );
    f.write("other", "x.py");
    assert_eq!(f.decide("a", "python3 x.py", false).verdict, Verdict::Allow);
    let codex = f.decide_as(Host::OpenCode, "other", "python3 x.py", (false, false));
    assert_eq!(codex.verdict, Verdict::Allow);
    // reading the file the session wrote runs nothing
    f.write("a", "y.py");
    assert_eq!(f.decide("a", "cat y.py", false).verdict, Verdict::Allow);
    // a test runner runs the project's code by design
    f.write("a", "test_y.py");
    assert_eq!(
        f.decide("a", "pytest test_y.py", false).verdict,
        Verdict::Allow
    );
    assert_eq!(
        f.decide("a", "python -m pytest", false).verdict,
        Verdict::Allow
    );
}

#[test]
fn a_shell_write_and_a_write_in_the_same_call_count() {
    let f = fixture();
    f.ran("a", &shell("echo 'cat ~/.s''sh/id_rsa' > x.sh"), None);
    assert!(asks(&f.decide("a", "bash x.sh", false)));
    assert!(asks(&f.decide("a", "./x.sh", false)));
    assert!(asks(&f.decide(
        "b",
        "cat > y.sh <<'EOF'\necho hi\nEOF\nsh y.sh",
        false
    )));
}

#[test]
fn a_script_written_by_inline_code_counts_as_written() {
    let f = fixture();
    f.ran(
        "a",
        &shell(r#"python3 -c 'open("x.py","w").write("print(1)")'"#),
        None,
    );
    assert!(asks(&f.decide("a", "python3 x.py", false)));
    f.ran(
        "a",
        &shell(r#"node -e "require('fs').writeFileSync('y.js','1')""#),
        None,
    );
    assert!(asks(&f.decide("a", "node y.js", false)));
    // code that writes another file still runs the one the session wrote
    assert!(asks(&f.decide(
        "a",
        r#"python3 -c 'open("log.txt","w").write("x"); import runpy; runpy.run_path("x.py")'"#,
        false
    )));
    // code that only read it records nothing
    f.ran(
        "b",
        &shell(r#"python3 -c 'print(open("x.py").read())'"#),
        None,
    );
    assert_eq!(f.decide("b", "python3 x.py", false).verdict, Verdict::Allow);
}

#[test]
fn a_session_grant_after_the_last_write_answers_it() {
    let f = fixture();
    let wrote = f.write("a", "x.py");
    assert!(asks(&f.decide("a", "python3 x.py", false)));
    f.grant("a", "python3 x.py", wrote);
    let answered = f.decide("a", "python3 x.py", false);
    assert_eq!(answered.verdict, Verdict::Allow, "{answered:?}");
    // another call is not answered by it
    assert!(asks(&f.decide("a", "python3 -u x.py", false)));
    // rewritten after the grant: the person approved other code
    f.write("a", "x.py");
    assert!(asks(&f.decide("a", "python3 x.py", false)));
}

#[test]
fn a_deny_or_an_ask_stays_as_it_was() {
    let f = fixture();
    f.write("a", "x.py");
    let action = shell("python3 x.py");
    let compiled = f.compiled();
    let code = Call {
        home: &f.home,
        host: Host::GeminiCli,
        session: "a",
        action: &action,
        cwd: &f.proj,
        user_home: "/home/u",
        writes: &[],
        within_run: false,
    };
    for verdict in [Verdict::Ask, Verdict::Deny] {
        let decision = Decision::single(verdict, "other", "why");
        let got = checked(&code, &compiled, &f.store, decision.clone(), (0, &|| false)).unwrap();
        assert_eq!(got, decision);
    }
}

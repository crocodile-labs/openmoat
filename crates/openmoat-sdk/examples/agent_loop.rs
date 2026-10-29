//! An agent loop that checks every tool call with OpenMoat before it runs.
//!
//! The "model" here is a script of tool calls, so the example runs without a
//! model or a network; swap `next_call` for your model's tool-use output. The
//! tools are real: they read and write files on this machine, but only after
//! the engine said they may.
//!
//!     cargo run -p openmoat-sdk --example agent_loop
//!
//! The rules the loop keeps (docs/SDK.md):
//! - `deny`: the call does not run; the model is told why.
//! - `ask`: the call runs only if a person approves this exact call.
//! - `defer`: this product has no permission flow of its own, so it asks too.
//! - `allow`: the call runs, exactly as decided, never a value rebuilt from it.

use std::path::{Path, PathBuf};

use openmoat_sdk::{Action, Context, DEFAULT_POLICY, Engine, Facts, Policy, Session, Verdict};

/// A tool call the model asked for.
#[derive(Debug, Clone)]
enum ToolCall {
    ReadFile { path: String },
    WriteFile { path: String, contents: String },
}

impl ToolCall {
    /// The action OpenMoat decides: what the tool will touch, nothing less.
    fn action(&self) -> Action {
        match self {
            Self::ReadFile { path } => Action::read(path.clone()),
            Self::WriteFile { path, .. } => Action::write(path.clone()),
        }
    }
}

/// What the loop reports back to the model for one call.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Ran(String),
    Refused { verdict: Verdict, reason: String },
}

/// The person who answers `ask`: in a real product, a prompt in your UI.
type Approver<'a> = &'a dyn Fn(&ToolCall, &str) -> bool;

struct Agent {
    engine: Engine,
    session: Session,
}

impl Agent {
    fn new(home: &Path, project: &Path) -> Result<Self, openmoat_sdk::Error> {
        let mut context = Context::new(slash(home), slash(project))
            .project(slash(project))
            .case_insensitive_paths(cfg!(any(windows, target_os = "macos")));
        // macOS's temporary directories are links (`/var` → `/private/var`).
        if let (Ok(real_home), Ok(real_project)) = (home.canonicalize(), project.canonicalize()) {
            context = context
                .real_home(slash(&real_home))
                .real_project(slash(&real_project));
        }
        let engine = Engine::new(Policy::parse(DEFAULT_POLICY)?, &context)?;
        Ok(Self {
            engine,
            session: Session::new(),
        })
    }

    /// Decide `call`, and run it only when the decision lets it.
    fn step(&mut self, call: &ToolCall, approve: Approver<'_>) -> Outcome {
        let action = call.action();
        // Report where every path really leads, so a link cannot carry the call
        // past a rule. These are the facts the decision is bound to.
        let facts = self
            .engine
            .paths(&action)
            .into_iter()
            .filter_map(|path| resolved(&path).map(|real| (path, real)))
            .fold(Facts::new(), |facts, (path, real)| facts.link(path, real));
        let decision = self.engine.decide_with(&action, &facts, &self.session);
        let may_run = match decision.verdict {
            Verdict::Allow => true,
            Verdict::Ask | Verdict::Defer => approve(call, &decision.reason()),
            // `Deny`, and any verdict this example does not know: never run.
            _ => false,
        };
        if !may_run {
            return Outcome::Refused {
                verdict: decision.verdict,
                reason: decision.reason(),
            };
        }
        let outcome = run(call);
        self.session.record(&self.engine, &action, &facts);
        outcome
    }
}

fn run(call: &ToolCall) -> Outcome {
    let result = match call {
        ToolCall::ReadFile { path } => std::fs::read_to_string(path),
        ToolCall::WriteFile { path, contents } => {
            std::fs::write(path, contents).map(|()| format!("wrote {} bytes", contents.len()))
        }
    };
    match result {
        Ok(text) => Outcome::Ran(text),
        Err(e) => Outcome::Ran(format!("error: {e}")),
    }
}

/// `path` through its deepest existing ancestor's real location, when that
/// differs from `path`.
fn resolved(path: &str) -> Option<String> {
    let mut existing = PathBuf::from(path);
    let mut rest = Vec::new();
    while !existing.exists() {
        rest.push(existing.file_name()?.to_owned());
        existing = existing.parent()?.to_owned();
    }
    let mut real = existing.canonicalize().ok()?;
    real.extend(rest.iter().rev());
    let real = slash(&real);
    (real != path).then_some(real)
}

/// An absolute path in the slash-separated form the engine reads.
fn slash(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    // Windows' verbatim prefix from `canonicalize`.
    text.strip_prefix("//?/")
        .map_or(text.clone(), str::to_owned)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("openmoat-agent-loop-{}", std::process::id()));
    let home = dir.join("home");
    let project = home.join("app");
    std::fs::create_dir_all(home.join(".ssh"))?;
    std::fs::create_dir_all(&project)?;
    std::fs::write(home.join(".ssh/id_ed25519"), "not a real key\n")?;
    std::fs::write(project.join("README.md"), "# app\n")?;

    let mut agent = Agent::new(&home, &project)?;
    let script = [
        ToolCall::ReadFile {
            path: slash(&project.join("README.md")),
        },
        ToolCall::ReadFile {
            path: slash(&home.join(".ssh/id_ed25519")),
        },
        ToolCall::WriteFile {
            path: slash(&project.join("NOTES.md")),
            contents: "checked by OpenMoat\n".into(),
        },
    ];
    let nobody = |_: &ToolCall, _: &str| false;
    for call in &script {
        println!("{call:?}\n  -> {:?}", agent.step(call, &nobody));
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Agent, Outcome, ToolCall, Verdict, slash};

    struct Dirs {
        _dir: tempfile::TempDir,
        home: std::path::PathBuf,
        project: std::path::PathBuf,
    }

    fn dirs() -> Dirs {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let project = home.join("app");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(home.join(".ssh/id_ed25519"), "SECRET").unwrap();
        std::fs::write(project.join("README.md"), "# app").unwrap();
        Dirs {
            _dir: dir,
            home,
            project,
        }
    }

    fn read(path: &std::path::Path) -> ToolCall {
        ToolCall::ReadFile { path: slash(path) }
    }

    const NOBODY: &dyn Fn(&ToolCall, &str) -> bool = &|_, _| false;

    #[test]
    fn allowed_calls_run_and_denied_ones_never_do() {
        let h = dirs();
        let mut agent = Agent::new(&h.home, &h.project).unwrap();
        assert_eq!(
            agent.step(&read(&h.project.join("README.md")), NOBODY),
            Outcome::Ran("# app".into())
        );
        let Outcome::Refused { verdict, reason } =
            agent.step(&read(&h.home.join(".ssh/id_ed25519")), &|_, _| true)
        else {
            panic!("the key was read");
        };
        // A deny is not offered to the approver, who would have said yes.
        assert_eq!(verdict, Verdict::Deny);
        assert!(reason.contains("secret material"), "{reason}");

        let notes = h.project.join("NOTES.md");
        let write = ToolCall::WriteFile {
            path: slash(&notes),
            contents: "hi".into(),
        };
        assert!(matches!(agent.step(&write, NOBODY), Outcome::Ran(_)));
        assert_eq!(std::fs::read_to_string(&notes).unwrap(), "hi");
    }

    #[test]
    fn a_call_that_needs_a_person_waits_for_one() {
        let h = dirs();
        let mut agent = Agent::new(&h.home, &h.project).unwrap();
        // A write outside the project: no rule allows it, so the policy's
        // catch-all leaves it to this product's own flow, which asks.
        let outside = h.home.join("todo.txt");
        let call = ToolCall::WriteFile {
            path: slash(&outside),
            contents: "buy milk".into(),
        };
        let refused = agent.step(&call, NOBODY);
        assert!(
            matches!(refused, Outcome::Refused { verdict, .. } if verdict != Verdict::Deny),
            "{refused:?}"
        );
        assert!(!outside.exists());
        assert!(matches!(agent.step(&call, &|_, _| true), Outcome::Ran(_)));
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "buy milk");
    }

    /// A link inside the project to `~/.ssh` is followed, not trusted.
    #[cfg(unix)]
    #[test]
    fn a_symlink_cannot_carry_a_read_past_a_rule() {
        let h = dirs();
        std::os::unix::fs::symlink(h.home.join(".ssh"), h.project.join("keys")).unwrap();
        let mut agent = Agent::new(&h.home, &h.project).unwrap();
        let outcome = agent.step(&read(&h.project.join("keys/id_ed25519")), NOBODY);
        assert!(
            matches!(
                outcome,
                Outcome::Refused {
                    verdict: Verdict::Deny,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }
}

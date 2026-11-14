use std::path::{Path, PathBuf};

use openmoat_core::{DEFAULT_POLICY, Policy, Secret};
use serde_json::Value;

use super::*;
use crate::integrity::Lock;
use crate::sandbox::Report;
use crate::sandbox::backend::{Pin, SecretMask, Undo};
use crate::sandbox::install::Rendered;

const HOME: &str = "/Users/me";

/// A fourth format's settings: the directory it lets commands write, and the
/// file it was generated for.
#[derive(Debug)]
struct FakeSettings {
    writable: Vec<String>,
    file: PathBuf,
    report: Report,
}

impl Output for FakeSettings {
    fn render(&self, _home: &Home, _host: Host, current: &str) -> Result<Option<Rendered>> {
        Ok(Some(Rendered {
            text: format!("{current}fake\n"),
            claude_rules: None,
        }))
    }

    fn report(&self) -> &Report {
        &self.report
    }

    fn shown(&self) -> Result<String> {
        Ok(crate::context::path_string(&self.file))
    }

    fn problems(
        &self,
        _home: &Home,
        _path: &Path,
        _plan: &Plan,
        _lock: Option<&Lock>,
    ) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn writable_dirs(&self) -> Vec<String> {
        self.writable.clone()
    }

    fn secret_masks<'a>(&self, _settings: &Value, _secrets: &'a [Secret]) -> Vec<SecretMask<'a>> {
        Vec::new()
    }
}

/// A fourth backend, known only to this test.
struct FakeBackend;

static FAKE: FakeBackend = FakeBackend;

impl SandboxBackend for FakeBackend {
    fn generate(&self, input: &Input<'_>, settings: &Path) -> Result<Box<dyn Output>> {
        Ok(Box::new(FakeSettings {
            writable: input
                .homes
                .iter()
                .map(|h| format!("{h}/fake-agent"))
                .collect(),
            file: settings.to_path_buf(),
            report: Report::default(),
        }))
    }

    fn undo(&self) -> Undo {
        Undo::Json(|_| false)
    }

    fn pin(&self) -> Pin {
        Pin::Whole(|_| Ok(false))
    }
}

/// Each sandboxed host's backend, with a settings file under [`HOME`].
fn listed() -> Vec<Sandbox> {
    install::hosts()
        .map(|host| {
            let backend = install::backend(host).expect("a sandboxed host has a backend");
            (
                host,
                backend,
                Path::new(HOME).join(host.id()).join("settings"),
            )
        })
        .collect()
}

fn plan_with(sandboxes: Vec<Sandbox>) -> Plan {
    let policy = Policy::parse(DEFAULT_POLICY).expect("default policy");
    let ir = lower_for_hosts(&policy, HOME, None, Vec::new(), false).expect("lowers");
    let homes = [HOME.to_owned()];
    let input = Input {
        ir: &ir,
        proxy_port: None,
        homes: &homes,
        binary_paths: &[],
        linux: false,
    };
    Plan {
        default_read_roots: false,
        proxy_port: None,
        serve_without_credential: false,
        outputs: generate(&input, sandboxes).expect("generates"),
    }
}

/// A backend for a host the list does not know joins the plan through the
/// same path as the listed ones, and what the plan reports and lets commands
/// write comes from it, with no edit to the plan or to `sandbox.rs`.
#[test]
fn a_fourth_backend_joins_the_plan_without_naming_it() {
    let new_host = Host::ALL
        .into_iter()
        .find(|h| install::backend(*h).is_none())
        .expect("a host without a sandbox stands in for a new one");
    let file = Path::new(HOME).join("new-agent/sandbox.json");
    let mut sandboxes = listed();
    sandboxes.push((new_host, &FAKE, file.clone()));
    let plan = plan_with(sandboxes);

    let output = plan
        .output(new_host)
        .expect("the new host's settings are in the plan");
    assert_eq!(output.shown().unwrap(), crate::context::path_string(&file));
    assert!(std::ptr::eq(
        install::report(new_host, &plan),
        output.report()
    ));
    let dirs = plan.writable_dirs();
    assert!(dirs.contains(&format!("{HOME}/fake-agent")), "{dirs:?}");
    for host in install::hosts() {
        assert!(plan.output(host).is_some(), "{host:?} left the plan");
    }
}

/// The plan's writable directories are each backend's, in the list's order,
/// and a host without a sandbox has no settings in it.
#[test]
fn writable_dirs_are_every_backends_own() {
    let plan = plan_with(listed());
    let expected: Vec<String> = install::hosts()
        .flat_map(|host| plan.output(host).expect("listed").writable_dirs())
        .collect();
    assert_eq!(plan.writable_dirs(), expected);
    let unsandboxed = Host::ALL
        .into_iter()
        .filter(|h| install::backend(*h).is_none());
    for host in unsandboxed {
        assert!(plan.output(host).is_none(), "{host:?}");
        assert_eq!(install::report(host, &plan), &Report::default());
    }
}

//! The policy compiler agrees with the hook decision (ADR-019).
//!
//! For every conformance fixture that is a file read, file write, network or
//! fetch action, the lowered IR's verdict on the atoms the engine evaluates
//! must be the engine's verdict with `ask` and `defer` read as `deny`. A wider IR verdict
//! (an allow the engine would not give) is a bypass of every OS layer; a
//! narrower one would be allowed by ADR-019 but must then be reported as a
//! loss, and the default policy has none on these fixtures.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core::ir::{Effect, lower};
use openmoat_core::{
    Action, CompiledPolicy, DEFAULT_POLICY, EvalContext, MapPathResolver, NoResolver, Policy,
    Verdict,
};
use serde::Deserialize;

/// The fields of a conformance fixture this test needs; `conformance.rs`
/// validates the rest of the schema.
#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    action: FixtureAction,
    #[serde(default)]
    links: BTreeMap<String, String>,
    context: Option<FixtureContext>,
}

#[derive(Debug, Deserialize)]
struct FixtureAction {
    fs_read: Option<String>,
    fs_write: Option<String>,
    net: Option<String>,
    fetch: Option<String>,
    patch: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct FixtureContext {
    cwd: String,
    project: Option<String>,
    real_project: Option<String>,
    real_home: Option<String>,
}

impl FixtureAction {
    /// The action when it is one an OS layer governs, else `None`.
    fn lowerable(self) -> Option<Action> {
        [
            self.fs_read.map(|path| Action::FsRead { path }),
            self.fs_write.map(|path| Action::FsWrite { path }),
            self.net.map(|url| Action::Net { url }),
            self.fetch.map(|url| Action::Fetch { url }),
            self.patch.map(|writes| Action::Patch { writes }),
        ]
        .into_iter()
        .flatten()
        .next()
    }
}

fn fixtures() -> Vec<Fixture> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    files
        .iter()
        .flat_map(|f| {
            openmoat_core::yaml::from_str::<Vec<Fixture>>(&fs::read_to_string(f).unwrap())
                .unwrap_or_else(|e| panic!("{}: {e}", f.display()))
        })
        .collect()
}

#[test]
fn ir_verdicts_match_the_engine_on_every_lowerable_fixture() {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let base = EvalContext {
        home: "/Users/me".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    };
    let (mut checked, mut wider, mut narrower) = (0, Vec::new(), Vec::new());
    for fixture in fixtures() {
        let Some(action) = fixture.action.lowerable() else {
            continue;
        };
        let ctx = match fixture.context {
            None => base.clone(),
            Some(c) => EvalContext {
                cwd: c.cwd,
                project: c.project,
                real_project: c.real_project,
                real_home: c.real_home,
                ..base.clone()
            },
        };
        let links = MapPathResolver {
            links: fixture.links,
            ..MapPathResolver::default()
        };
        let engine = CompiledPolicy::compile(&policy, &ctx).unwrap();
        let ir = lower(&policy, &ctx).unwrap().checker().unwrap();
        let hook_allows =
            engine.decide_with(&action, &NoResolver, &links).verdict == Verdict::Allow;
        // An action without a host is unparseable: the hook asks, and no OS
        // layer ever sees a connection to judge.
        let (atoms, None) = engine.atoms(&action, &links) else {
            assert!(!hook_allows, "{}", fixture.id);
            continue;
        };
        let ir_allows = atoms
            .iter()
            .all(|atom| ir.check(atom) == Some(Effect::Allow));
        checked += 1;
        match (hook_allows, ir_allows) {
            (false, true) => wider.push(fixture.id),
            (true, false) => narrower.push(fixture.id),
            _ => {}
        }
    }
    assert!(
        wider.is_empty(),
        "the IR allows what the hook does not: {wider:?}"
    );
    assert!(
        narrower.is_empty(),
        "the IR denies what the hook allows: {narrower:?}"
    );
    assert!(
        checked >= 40,
        "only {checked} lowerable fixtures were compared"
    );
}

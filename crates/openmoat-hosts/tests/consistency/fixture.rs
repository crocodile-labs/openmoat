//! The conformance fixture a row names, read from `tests/conformance/*.yaml`.

use std::fs;
use std::path::{Path, PathBuf};

use super::{Expect, Fixture, Intent, setup};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The conformance fixture `id`, which must be a plain intent.
pub(super) fn fixture(id: &str) -> (Intent, Expect, setup::Setup) {
    let dir = repo_root().join("tests/conformance");
    for name in ["attacks.yaml", "review.yaml", "benign.yaml"] {
        let text = fs::read_to_string(dir.join(name)).expect("conformance file");
        let fixtures: Vec<Fixture> = openmoat_core::yaml::from_str(&text).expect(name);
        let Some(f) = fixtures.into_iter().find(|f| f.id == id) else {
            continue;
        };
        let extras = [&f.repo, &f.links, &f.resolve];
        assert!(
            extras.iter().all(|e| e.is_none()),
            "{id}: not a plain intent (repo, links or resolve)"
        );
        let setup = setup::Setup::read(id, f.session, f.context);
        let a = f.action;
        let intent = match (a.shell, a.fs_read, a.fs_write, a.fetch) {
            (Some(c), None, None, None) => Intent::Shell(c),
            (None, Some(p), None, None) => Intent::Read(p),
            (None, None, Some(p), None) => Intent::Write(p),
            (None, None, None, Some(u)) => Intent::Fetch(u),
            _ => panic!("{id}: the action is not one shell, fs_read, fs_write or fetch"),
        };
        return (intent, f.expect, setup);
    }
    panic!("no conformance fixture `{id}`");
}

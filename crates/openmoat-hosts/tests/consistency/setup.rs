//! What a row's fixture sets besides its action: the earlier calls of the
//! session (`session:`), whose taint the call is decided with, and the
//! evaluation context (`context:`), such as a moved state directory. Both are
//! the same whichever host sends the call, so the hosts must agree under them
//! too; a session-taint review a host loses (a fetch it does not report, a
//! write it sends without its path) shows up as a mismatch.

use std::collections::BTreeMap;

use openmoat_core::{Action, CompiledPolicy, EvalContext, MapPathResolver, Taint};
use serde_json::Value;

use super::{CWD, HOME, Intent};

/// A row's session and context, read from its fixture.
#[derive(Debug, Default)]
pub(super) struct Setup {
    /// The earlier calls of the session, oldest first.
    session: Vec<Intent>,
    /// The fixture's `context:`, which must keep the routes' `cwd` and project.
    context: Option<Value>,
}

impl Setup {
    /// `session` and `context` as fixture `id` gives them; panics on a step or
    /// key the routes cannot send alike.
    pub(super) fn read(id: &str, session: Option<Vec<Value>>, context: Option<Value>) -> Self {
        let session = session
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(n, step)| intent_of(&format!("{id}.session[{n}]"), step))
            .collect();
        if let Some(context) = &context {
            let keys = ["cwd", "project", "moved_dirs", "real_home", "real_project"];
            let object = context.as_object().expect("`context` is a mapping");
            for key in object.keys() {
                assert!(keys.contains(&key.as_str()), "{id}: context key `{key}`");
            }
            for key in ["cwd", "project"] {
                let value = object.get(key).and_then(Value::as_str);
                assert!(
                    value.is_none_or(|v| v == CWD),
                    "{id}: context `{key}` must be {CWD}, which every route sends"
                );
            }
        }
        Self { session, context }
    }

    /// The context the call is decided in, with `cwd` the request's.
    pub(super) fn context(&self, cwd: String) -> EvalContext {
        let text = |key: &str| {
            self.context
                .as_ref()
                .and_then(|c| c.get(key))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let moved: BTreeMap<String, String> = self
            .context
            .as_ref()
            .and_then(|c| c.get("moved_dirs"))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        EvalContext {
            home: HOME.into(),
            project: Some(CWD.into()),
            real_home: text("real_home"),
            real_project: text("real_project"),
            moved_dirs: moved.into_iter().collect(),
            cwd,
            case_insensitive_paths: false,
        }
    }

    /// The taint the session's earlier calls leave, as the conformance suite
    /// folds it.
    pub(super) fn taint(&self, compiled: &CompiledPolicy, links: &MapPathResolver) -> Taint {
        let mut taint = Taint::default();
        for intent in &self.session {
            taint.absorb(compiled.exposure(&action(intent), CWD, links));
        }
        taint
    }
}

/// The action `intent` is, as the engine reads it.
fn action(intent: &Intent) -> Action {
    match intent {
        Intent::Shell(command) => Action::Shell {
            command: command.clone(),
        },
        Intent::Read(path) => Action::FsRead { path: path.clone() },
        Intent::Write(path) => Action::FsWrite { path: path.clone() },
        Intent::Fetch(url) => Action::Fetch { url: url.clone() },
    }
}

/// The one shell, file or fetch call `step` of fixture `what` names.
fn intent_of(what: &str, step: &Value) -> Intent {
    let object = step.as_object().expect("a call is a mapping");
    let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_owned);
    assert!(
        object.len() == 1,
        "{what}: not one shell, fs_read, fs_write or fetch call"
    );
    match (
        text("shell"),
        text("fs_read"),
        text("fs_write"),
        text("fetch"),
    ) {
        (Some(c), None, None, None) => Intent::Shell(c),
        (None, Some(p), None, None) => Intent::Read(p),
        (None, None, Some(p), None) => Intent::Write(p),
        (None, None, None, Some(u)) => Intent::Fetch(u),
        _ => panic!("{what}: not one shell, fs_read, fs_write or fetch call"),
    }
}

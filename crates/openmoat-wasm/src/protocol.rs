//! The requests the module answers, one JSON object each, tagged by `op`.
//!
//! | `op` | Fields | `ok` holds |
//! |---|---|---|
//! | `info` | | `version`, `policy_schema_version`, `abi` |
//! | `default_policy` | | `policy`: the shipped default policy's YAML |
//! | `compile` | `policy` (YAML), `context`, `repository`? (`{policy, trusted}`) | `engine`: a handle |
//! | `decide` | `engine`, `action`, `facts`?, `session`? | `verdict`, `rules`, `reasons`, `context` |
//! | `record` | `engine`, `action`, `facts`?, `session`? | `session`: the session after the call ran |
//! | `paths` | `engine`, `action` | `paths` |
//! | `release` | `engine` | `released`: whether the handle named an engine |
//!
//! `action`, `context` and `facts` have the JSON forms of `openmoat_sdk`'s
//! `Action`, `Context` and `Facts`. `session` is opaque text the module wrote
//! (a `record` answer), passed back unchanged. The response is `{"ok": {…}}`, or
//! `{"error": "…"}` for a request that cannot be answered; a caller must not run
//! a call it holds no decision for. Unknown fields are errors.

use serde::Deserialize;

use openmoat_sdk::{
    Action, Context, DEFAULT_POLICY, Decision, Engine, Facts, POLICY_SCHEMA_VERSION, Policy,
    Session, VERSION,
};

use crate::engines;
use crate::json::Object;

/// The version of this request protocol. Bumped only by an incompatible
/// change; a new `op` or optional field keeps it.
pub const ABI_VERSION: u32 = 1;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    // Empty struct variants, not unit ones: serde ignores extra fields beside
    // the tag of a unit variant, and an unknown field must be an error.
    Info {},
    DefaultPolicy {},
    Compile {
        policy: String,
        context: Context,
        #[serde(default)]
        repository: Option<Repository>,
    },
    Decide {
        engine: u32,
        action: Action,
        #[serde(default)]
        facts: Option<Facts>,
        #[serde(default)]
        session: Option<String>,
    },
    Record {
        engine: u32,
        action: Action,
        #[serde(default)]
        facts: Option<Facts>,
        #[serde(default)]
        session: Option<String>,
    },
    Paths {
        engine: u32,
        action: Action,
    },
    Release {
        engine: u32,
    },
}

/// A repository policy merged into the compiled one (ADR-022).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Repository {
    policy: String,
    #[serde(default)]
    trusted: bool,
}

/// Answer one request: `{"ok": …}` or `{"error": "…"}`.
#[must_use]
pub fn handle(request: &[u8]) -> String {
    let answer = std::str::from_utf8(request)
        .map_err(|_| "request is not UTF-8".to_owned())
        .and_then(|text| {
            openmoat_core::yaml::from_str::<Request>(text).map_err(|e| format!("bad request: {e}"))
        })
        .and_then(answer);
    match answer {
        Ok(ok) => Object::new().object("ok", ok).finish(),
        Err(message) => Object::new().string("error", &message).finish(),
    }
}

fn answer(request: Request) -> Result<Object, String> {
    match request {
        Request::Info {} => Ok(Object::new()
            .string("version", VERSION)
            .number("policy_schema_version", POLICY_SCHEMA_VERSION)
            .number("abi", ABI_VERSION)),
        Request::DefaultPolicy {} => Ok(Object::new().string("policy", DEFAULT_POLICY)),
        Request::Compile {
            policy,
            context,
            repository,
        } => compile(&policy, &context, repository.as_ref()),
        Request::Decide {
            engine,
            action,
            facts,
            session,
        } => {
            let session = session_from(session.as_deref())?;
            let facts = facts.unwrap_or_default();
            with_engine(engine, |e| {
                decision(&e.decide_with(&action, &facts, &session))
            })
        }
        Request::Record {
            engine,
            action,
            facts,
            session,
        } => {
            let mut session = session_from(session.as_deref())?;
            let facts = facts.unwrap_or_default();
            with_engine(engine, |e| session.record(e, &action, &facts))?;
            let text = openmoat_core::yaml::to_string(&session)
                .map_err(|e| format!("cannot write the session: {e}"))?;
            Ok(Object::new().string("session", &text))
        }
        Request::Paths { engine, action } => with_engine(engine, |e| {
            Object::new().strings("paths", &e.paths(&action))
        }),
        Request::Release { engine } => {
            Ok(Object::new().boolean("released", engines::release(engine)))
        }
    }
}

fn compile(
    policy: &str,
    context: &Context,
    repository: Option<&Repository>,
) -> Result<Object, String> {
    let mut policy = Policy::parse(policy).map_err(|e| e.to_string())?;
    if let Some(repo) = repository {
        policy = policy
            .with_repository(&repo.policy, repo.trusted)
            .map_err(|e| e.to_string())?;
    }
    let engine = Engine::new(policy, context).map_err(|e| e.to_string())?;
    let handle = engines::insert(engine).ok_or("no engine handles left")?;
    Ok(Object::new().number("engine", handle))
}

fn with_engine<T>(handle: u32, f: impl FnOnce(&Engine) -> T) -> Result<T, String> {
    engines::with(handle, f).ok_or_else(|| format!("no engine {handle}; compile one first"))
}

fn session_from(text: Option<&str>) -> Result<Session, String> {
    text.map_or_else(
        || Ok(Session::new()),
        |text| openmoat_core::yaml::from_str(text).map_err(|e| format!("bad session: {e}")),
    )
}

fn decision(d: &Decision) -> Object {
    Object::new()
        .string("verdict", d.verdict.as_str())
        .strings("rules", &d.rules)
        .strings("reasons", &d.reasons)
        .strings("context", &d.context)
}

#[cfg(test)]
mod tests;

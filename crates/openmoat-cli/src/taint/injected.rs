//! Injected input (ADR-057) kept in the audit database: what a session's
//! untrusted call outputs held, as keyed fingerprints, and the review a later
//! call that acts on it needs.
//!
//! The core finds the tokens ([`CompiledPolicy::injected_tokens`]) and decides
//! ([`CompiledPolicy::with_injected`]); this module keeps each token as
//! [`Key::fingerprint`] with the source that brought it in, never the text,
//! and answers the core's lookups from those rows.

use std::cell::RefCell;

use anyhow::{Context as _, Result};
use openmoat_audit::{NewInjected, Store, StoreError};
use openmoat_core::{Action, CompiledPolicy, Decision, InjectedLookup, InjectedToken};
use openmoat_hosts::Host;

use crate::home::Home;
use crate::proxy_session::Key;
use crate::realpath::FsPathResolver;

/// One untrusted call output to keep.
pub struct Output<'a> {
    pub host: Host,
    pub session: &'a str,
    /// The call that returned it.
    pub action: &'a Action,
    /// Where it ran.
    pub cwd: &'a str,
    pub text: &'a str,
}

/// Keep the fingerprints of `output`'s tokens when the call that returned it
/// read content an attacker may control; returns how many were added. A
/// local command or a file read keeps nothing.
pub fn record(
    home: &Home,
    store: &Store,
    policy: &CompiledPolicy<'_>,
    output: &Output<'_>,
) -> Result<usize> {
    let Some(source) = policy.output_source(output.action, output.cwd, &FsPathResolver) else {
        return Ok(0);
    };
    let tokens = policy.injected_tokens(output.action, output.cwd, output.text);
    if tokens.is_empty() {
        return Ok(0);
    }
    let key = Key::load_or_create(home)?;
    let rows: Vec<NewInjected> = tokens
        .iter()
        .map(|token| NewInjected {
            fingerprint: fingerprint(&key, token),
            source: source.clone(),
        })
        .collect();
    store
        .add_injected_inputs(output.host.id(), output.session, &rows)
        .context("keeping the fingerprints of this call's output in the audit log")
}

/// `decision` for `action`, tightened when a part of it came from untrusted
/// content `session` read. A session that kept no fingerprint costs one index
/// probe. A lookup that fails fails the call: the guard denies.
pub fn checked(
    home: &Home,
    store: &Store,
    (host, session): (Host, &str),
    policy: &CompiledPolicy<'_>,
    action: &Action,
    decision: Decision,
) -> Result<Decision> {
    let held = store
        .has_injected_inputs(host.id(), session)
        .context("reading this session's injected-input fingerprints")?;
    if !held {
        return Ok(decision);
    }
    let seen = Seen {
        store,
        key: Key::load_or_create(home)?,
        host: host.id(),
        session,
        failed: RefCell::new(None),
    };
    let decision = policy.with_injected(decision, action, &FsPathResolver, &seen);
    if let Some(error) = seen.failed.take() {
        return Err(error).context("reading this session's injected-input fingerprints");
    }
    Ok(decision)
}

fn fingerprint(key: &Key, token: &InjectedToken) -> String {
    key.fingerprint(token.kind.as_str(), &token.text)
}

/// The core's view of one session's fingerprints.
struct Seen<'a> {
    store: &'a Store,
    key: Key,
    host: &'a str,
    session: &'a str,
    /// The first lookup that failed: the core's lookup cannot fail, so the
    /// error is kept and the call fails after it.
    failed: RefCell<Option<StoreError>>,
}

impl InjectedLookup for Seen<'_> {
    fn source_of(&self, token: &InjectedToken) -> Option<String> {
        let fp = fingerprint(&self.key, token);
        match self.store.injected_source(self.host, self.session, &fp) {
            Ok(source) => source,
            Err(error) => {
                self.failed.borrow_mut().get_or_insert(error);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;

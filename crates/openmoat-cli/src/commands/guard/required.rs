//! The guard's check of the protection level the policy requires (ADR-064):
//! a call of an agent below it is denied with `protection-required`,
//! governed or not. The level and the deny are `crate::protection::required`'s.

use openmoat_core::{Decision, Policy};
use openmoat_hosts::{HookRequest, Host};

use crate::context;
use crate::home::Home;
use crate::integrity::Drift;
use crate::protection::required;

/// What the level of one call is read from.
pub(super) struct Call<'a> {
    /// The home the lock check returned.
    pub home: &'a Home,
    pub host: Host,
    /// The settings drift the call is decided through, part of the sandbox
    /// answer's key ([`crate::protection::os_sandboxed_by_lock`]).
    pub drifted: &'a [Drift],
    /// The call came through `openmoat run`, whose sandbox holds the agent.
    pub within_run: bool,
}

/// The deny for `call` when its agent is below the level `policy` requires;
/// `None` when nothing is required (nothing is read then) or it meets it.
pub(super) fn unmet(call: &Call<'_>, policy: &Policy) -> Option<Decision> {
    required::unmet(policy, call.host, || {
        required::in_force(call.home, call.host, call.drifted, call.within_run)
    })
}

/// `decision` (the host's own answer for a tool OpenMoat does not govern),
/// or the deny of [`unmet`]. Such a call reads no policy otherwise, so this
/// one reads what a requirement needs of it ([`required::policy_in`]: no
/// signature check, no process). A policy that cannot be read leaves
/// `decision` as it is: whether a level is required cannot be told, and
/// every governed call of the session is denied with `kernel-error` for the
/// same reason.
pub(super) fn ungoverned(call: &Call<'_>, request: &HookRequest, decision: Decision) -> Decision {
    let cwd = request
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_dir, Ok);
    let policy = cwd
        .map_err(anyhow::Error::from)
        .and_then(|cwd| context::eval_context(call.home, Some(&cwd), None))
        .and_then(|ctx| required::policy_in(call.home, &ctx));
    policy
        .ok()
        .and_then(|policy| unmet(call, &policy))
        .unwrap_or(decision)
}

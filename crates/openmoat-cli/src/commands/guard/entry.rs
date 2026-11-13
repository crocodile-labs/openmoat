//! What the hook that ran says about itself, besides its payload: the event
//! its entry named on the guard's command line (`--event`), for an agent whose
//! payloads name none (`HookSpec::names_event`), so the entry, never the
//! payload, says which event a payload is for; and whether a host running
//! another host's hook set its variable.

use std::sync::OnceLock;

use openmoat_hosts::Host;

static EVENT: OnceLock<Option<String>> = OnceLock::new();

/// Record `event`, the guard's `--event`, once as the guard starts.
pub(super) fn set(event: Option<String>) {
    let _ = EVENT.set(event);
}

/// The event the entry named; `None` for every entry that names none
/// (`openmoat_hosts::Host::parse_request_as`).
pub(super) fn event() -> Option<&'static str> {
    EVENT.get().and_then(Option::as_deref)
}

/// Whether this hook has the variable of a host running another host's hook.
pub(super) fn caller_set() -> bool {
    Host::caller_variable().is_some_and(|variable| std::env::var_os(variable).is_some())
}

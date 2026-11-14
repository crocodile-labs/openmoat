//! What the hook that ran says about itself, besides its payload: the event
//! its entry named on the guard's command line (`--event`), for an agent whose
//! payloads name none (`HookSpec::names_event`), so the entry, never the
//! payload, says which event a payload is for; and whether a host running
//! another host's hook set its variable.

use std::sync::{Mutex, OnceLock, PoisonError};

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

static PACKAGE: OnceLock<bool> = OnceLock::new();

/// A payload `--plugin` read before the call is decided, which the guard's
/// own read then takes instead of stdin, read once.
static PAYLOAD: Mutex<Option<String>> = Mutex::new(None);

/// Keep `payload`, read from stdin, for the guard's read.
pub(super) fn keep_payload(payload: String) {
    *PAYLOAD.lock().unwrap_or_else(PoisonError::into_inner) = Some(payload);
}

/// The payload [`keep_payload`] kept, once.
pub(super) fn kept_payload() -> Option<String> {
    PAYLOAD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
}

/// Record, once as the guard starts, whether it runs for a package of the
/// agent's own plugin channel (`--plugin`, ADR-099).
pub(super) fn set_package(yes: bool) {
    let _ = PACKAGE.set(yes);
}

/// Whether the guard runs for a package (`--plugin`): what it records is
/// marked as the package's.
pub(super) fn from_package() -> bool {
    PACKAGE.get().copied().unwrap_or(false)
}

/// Whether this hook has the variable of a host running another host's hook.
pub(super) fn caller_set() -> bool {
    Host::caller_variable().is_some_and(|variable| std::env::var_os(variable).is_some())
}

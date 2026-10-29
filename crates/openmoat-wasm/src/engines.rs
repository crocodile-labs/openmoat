//! The engines a host has compiled, by handle.
//!
//! Handles are never reused: a handle the host released, or one it kept from
//! before, names no engine rather than someone else's.

use std::cell::RefCell;
use std::collections::BTreeMap;

use openmoat_sdk::Engine;

#[derive(Default)]
struct Registry {
    last: u32,
    engines: BTreeMap<u32, Engine>,
}

thread_local! {
    static REGISTRY: RefCell<Registry> = RefCell::new(Registry::default());
}

/// Keep `engine`; its handle, or `None` once 2³² − 1 handles were given out.
pub fn insert(engine: Engine) -> Option<u32> {
    REGISTRY.with_borrow_mut(|r| {
        let handle = r.last.checked_add(1)?;
        r.last = handle;
        r.engines.insert(handle, engine);
        Some(handle)
    })
}

/// Run `f` with the engine `handle` names, if any.
pub fn with<T>(handle: u32, f: impl FnOnce(&Engine) -> T) -> Option<T> {
    REGISTRY.with_borrow(|r| r.engines.get(&handle).map(f))
}

/// Drop the engine `handle` names; whether there was one.
pub fn release(handle: u32) -> bool {
    REGISTRY.with_borrow_mut(|r| r.engines.remove(&handle).is_some())
}

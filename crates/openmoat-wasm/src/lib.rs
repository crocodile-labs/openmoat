//! `openmoat-wasm`: the WebAssembly module behind the JavaScript SDK
//! (`sdk/js`), ADR-046.
//!
//! A plain C ABI, so the module needs no binding generator and imports
//! nothing: it cannot reach a network, a clock or a file, whatever runs it.
//! One request at a time, as JSON:
//!
//! 1. `openmoat_input(len)` returns where to write `len` bytes of a request.
//! 2. `openmoat_call()` handles it and returns the length of the response.
//! 3. `openmoat_output()` returns where the response is.
//!
//! The request and response shapes are in [`protocol`]. A call never panics by
//! design; if the module traps anyway, the JavaScript wrapper refuses every
//! later call, so a broken module never decides.

#![warn(missing_docs)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod buffers;
mod engines;
mod json;
pub mod protocol;

/// Where to write a request of `len` bytes; null when `len` is over 16 MiB.
/// Valid until the next call into the module.
#[expect(
    unsafe_code,
    reason = "a WebAssembly export needs a fixed symbol name; no unsafe block"
)]
#[unsafe(no_mangle)]
pub extern "C" fn openmoat_input(len: u32) -> *mut u8 {
    buffers::input(len)
}

/// Handle the request in the input buffer; returns the response's length.
#[expect(
    unsafe_code,
    reason = "a WebAssembly export needs a fixed symbol name; no unsafe block"
)]
#[unsafe(no_mangle)]
pub extern "C" fn openmoat_call() -> u32 {
    buffers::call(protocol::handle)
}

/// Where the last response is. Valid until the next call into the module.
#[expect(
    unsafe_code,
    reason = "a WebAssembly export needs a fixed symbol name; no unsafe block"
)]
#[unsafe(no_mangle)]
pub extern "C" fn openmoat_output() -> *const u8 {
    buffers::output()
}

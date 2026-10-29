//! The request and response buffers the host reads and writes through the
//! module's memory.
//!
//! The host writes into the input buffer through the pointer
//! [`input`] hands out, while no Rust reference to it is live; Rust only reads
//! it again inside [`call`]. A WebAssembly instance is single-threaded, so the
//! buffers are thread-locals.

use std::cell::RefCell;

/// The largest request accepted: far above any policy or tool call.
pub const MAX_REQUEST: u32 = 16 << 20;

thread_local! {
    static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// A zeroed input buffer of `len` bytes; null when `len` is too large.
pub fn input(len: u32) -> *mut u8 {
    if len > MAX_REQUEST {
        return std::ptr::null_mut();
    }
    INPUT.with_borrow_mut(|buffer| {
        buffer.clear();
        buffer.resize(len as usize, 0);
        buffer.as_mut_ptr()
    })
}

/// Run `handle` on the input buffer and keep its response for [`output`].
pub fn call(handle: impl FnOnce(&[u8]) -> String) -> u32 {
    let response = INPUT.with_borrow(|request| handle(request));
    OUTPUT.with_borrow_mut(|out| {
        *out = response.into_bytes();
        // A response never nears 4 GiB; if one did, answer with an error
        // rather than a truncated length.
        u32::try_from(out.len()).unwrap_or_else(|_| {
            *out = br#"{"error":"response too large"}"#.to_vec();
            30
        })
    })
}

/// The last response.
pub fn output() -> *const u8 {
    OUTPUT.with_borrow(Vec::as_ptr)
}

#[cfg(test)]
mod tests {
    use super::{MAX_REQUEST, call, input, output};

    #[test]
    fn a_request_written_through_the_pointer_reaches_the_handler() {
        let request = b"{\"op\":\"info\"}";
        let len = u32::try_from(request.len()).unwrap();
        let at = input(len);
        assert!(!at.is_null());
        assert!(host_write(at, request));
        let n = call(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
        assert_eq!(n, len);
        assert!(!output().is_null());
        assert!(input(MAX_REQUEST + 1).is_null());
    }

    /// Write `bytes` where the host would, through the thread-local the pointer
    /// came from (a test cannot write through the raw pointer without `unsafe`);
    /// whether `at` is that buffer.
    fn host_write(at: *mut u8, bytes: &[u8]) -> bool {
        super::INPUT.with_borrow_mut(|buffer| {
            let same = buffer.as_mut_ptr() == at;
            buffer.copy_from_slice(bytes);
            same
        })
    }

    #[test]
    fn the_error_fallback_length_matches_its_text() {
        assert_eq!(br#"{"error":"response too large"}"#.len(), 30);
    }
}

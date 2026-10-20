//! `moat init`, `moat status` and the lock read OpenClaw's `openclaw.json`, a
//! JSON5 file any process running as the user (an agent included) can write.
//! The parser must reject what it cannot read without panicking or recursing
//! without bound, and what it accepts must survive being written back as JSON.

#![no_main]

// `moat` is a binary crate with no library to link against, and the parser
// needs nothing beyond `anyhow` and `serde_json`, so the target compiles the
// one source file the CLI ships. The repository's one-file-per-module rule
// (crates/openmoat-core/tests/architecture.rs) covers `crates/`, not `fuzz/`.
// rustfmt would follow the file's `#[cfg(test)] mod tests;` from here and not
// find it; the file is formatted as part of the main workspace.
#[rustfmt::skip]
#[path = "../../crates/openmoat-cli/src/json5.rs"]
mod json5;

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = json5::parse(text) else {
        return;
    };
    // A caller that edits the file writes plain JSON; reading that back must
    // give the same value and no comments.
    let written = serde_json::to_string(&parsed.value).expect("a Value always serialises");
    let reread = json5::parse(&written).expect("written JSON reads as JSON5");
    assert_eq!(reread.value, parsed.value, "{written}");
    assert!(!reread.comments);
    // Plain JSON that serde_json reads must mean the same to this parser.
    if let Ok(json) = serde_json::from_str::<Value>(text) {
        assert_eq!(json, parsed.value, "{text}");
    }
});

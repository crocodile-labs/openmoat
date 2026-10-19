//! Nothing outside a host's own module under `openmoat-hosts/src/host/` should
//! name a host: what differs between hosts belongs in its `HostSpec` or its
//! adapter. The code that still does is listed below with how many lines name
//! one; the list only shrinks. A file that names a host on fewer lines than
//! listed fails too, so the list is lowered with the change that fixes it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Lines naming a `Host` variant, per file (relative to `crates/`), outside
/// `openmoat-hosts/src/host/` and test files. `lib.rs` defines the variants and
/// `registry.rs` maps them to their modules; the rest is to move.
const ALLOWED: &[(&str, usize)] = &[
    ("openmoat-cli/src/commands/allow.rs", 1),
    ("openmoat-cli/src/commands/doctor.rs", 2),
    ("openmoat-cli/src/commands/doctor/sandboxes.rs", 1),
    ("openmoat-cli/src/commands/doctor/warnings.rs", 1),
    ("openmoat-cli/src/commands/guard.rs", 1),
    ("openmoat-cli/src/commands/init.rs", 3),
    ("openmoat-cli/src/commands/sandbox.rs", 7),
    ("openmoat-cli/src/commands/status.rs", 1),
    ("openmoat-cli/src/commands/uninstall.rs", 6),
    ("openmoat-cli/src/context.rs", 3),
    ("openmoat-cli/src/hangs.rs", 1),
    ("openmoat-cli/src/install.rs", 10),
    ("openmoat-cli/src/install/dirs.rs", 5),
    ("openmoat-cli/src/integrity.rs", 1),
    ("openmoat-cli/src/mcp.rs", 1),
    ("openmoat-cli/src/mcp/pins.rs", 1),
    ("openmoat-cli/src/mcp/servers.rs", 10),
    ("openmoat-cli/src/mcp/wrap.rs", 1),
    ("openmoat-cli/src/sandbox.rs", 2),
    ("openmoat-cli/src/sandbox/install.rs", 19),
    ("openmoat-cli/src/taint.rs", 1),
    ("openmoat-hosts/src/lib.rs", 7),
    ("openmoat-hosts/src/registry.rs", 10),
    ("openmoat-hosts/src/wire/pre_tool_use.rs", 1),
];

const VARIANTS: [&str; 5] = [
    "Host::ClaudeCode",
    "Host::Codex",
    "Host::Cursor",
    "Host::Continue",
    "Host::OpenClaw",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether `line` names a variant as a whole word (`Host::Codex`, not
/// `Host::CodexLike`).
fn names_a_host(line: &str) -> bool {
    VARIANTS.iter().any(|variant| {
        line.match_indices(variant).any(|(at, _)| {
            !line[at + variant.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    })
}

#[test]
fn only_host_modules_name_a_host() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for root in ["openmoat-hosts/src", "openmoat-cli/src"] {
        rust_files(&crates.join(root), &mut files);
    }
    let mut found = BTreeMap::new();
    for file in files {
        let relative = file
            .strip_prefix(&crates)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if relative.starts_with("openmoat-hosts/src/host/")
            || relative.ends_with("/tests.rs")
            || relative.contains("/tests/")
        {
            continue;
        }
        let lines = fs::read_to_string(&file)
            .unwrap()
            .lines()
            .filter(|l| names_a_host(l))
            .count();
        if lines > 0 {
            found.insert(relative, lines);
        }
    }
    let allowed: BTreeMap<String, usize> = ALLOWED
        .iter()
        .map(|(file, lines)| ((*file).to_owned(), *lines))
        .collect();
    assert!(found.len() > 5, "the scan found too little: {found:?}");
    for (file, lines) in &found {
        let limit = allowed.get(file).copied().unwrap_or(0);
        assert!(
            *lines <= limit,
            "{file} names a host on {lines} lines (allowed {limit}): move what differs \
             into the host's spec or adapter"
        );
    }
    for (file, limit) in &allowed {
        let lines = found.get(file).copied().unwrap_or(0);
        assert_eq!(
            lines, *limit,
            "{file} now names a host on {lines} lines: lower its entry in ALLOWED"
        );
    }
}

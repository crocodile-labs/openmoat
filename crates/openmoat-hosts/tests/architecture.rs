//! Nothing outside a host's own module under `openmoat-hosts/src/host/` should
//! name a host: what differs between hosts belongs in its `HostSpec` or its
//! adapter. The code that still does is listed below with how many lines name
//! one; the list only shrinks. A file that names a host on fewer lines than
//! listed fails too, so the list is lowered with the change that fixes it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::Host;

/// Lines naming a `Host` variant, per file (relative to `crates/`), outside
/// `openmoat-hosts/src/host/` and test files. The host list in `host.rs` names
/// each host without the `Host::` prefix and is checked on its own below; the
/// rest is to move.
const ALLOWED: &[(&str, usize)] = &[
    ("openmoat-cli/src/hangs.rs", 1),
    ("openmoat-cli/src/mcp/pins.rs", 1),
    ("openmoat-cli/src/mcp/servers.rs", 2),
    ("openmoat-cli/src/mcp/wrap.rs", 1),
    // An inline test of what Claude Code, Codex and the Continue CLI answer.
    ("openmoat-hosts/src/lib.rs", 1),
];

/// `Host::<Variant>` for every host, from the host list itself.
fn variants() -> Vec<String> {
    Host::EVERY
        .iter()
        .map(|host| format!("Host::{host:?}"))
        .collect()
}

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
fn names_a_host(line: &str, variants: &[String]) -> bool {
    variants.iter().any(|variant| {
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
    let variants = variants();
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
            .filter(|l| names_a_host(l, &variants))
            .count();
        if lines > 0 {
            found.insert(relative, lines);
        }
    }
    let allowed: BTreeMap<String, usize> = ALLOWED
        .iter()
        .map(|(file, lines)| ((*file).to_owned(), *lines))
        .collect();
    assert!(found.len() > 3, "the scan found too little: {found:?}");
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

/// The host list in `host.rs` is the one place that names every host: one
/// `Variant => module` line per host, in [`Host::EVERY`] order, and one file
/// `host/<module>.rs` per line and no other.
#[test]
fn the_host_list_names_every_host_once_with_its_module() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let text = fs::read_to_string(src.join("host.rs")).unwrap();
    let list = text.split_once("hosts! {").unwrap().1;
    let list = list.split_once("\n}").unwrap().0;
    let lines: Vec<(&str, &str)> = list
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .map(|l| l.split_once(" => ").unwrap())
        .collect();
    let named: Vec<String> = lines.iter().map(|(v, _)| (*v).to_owned()).collect();
    let every: Vec<String> = Host::EVERY.iter().map(|h| format!("{h:?}")).collect();
    assert_eq!(named, every);
    let mut modules: Vec<String> = lines
        .iter()
        .map(|(_, rest)| rest.split([' ', ',']).next().unwrap().to_owned())
        .collect();
    modules.sort();
    let mut files: Vec<String> = fs::read_dir(src.join("host"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(modules, files, "a file under host/ is not on the list");
}

/// Lines of CLI and core source (relative to `crates/`, outside test files and
/// generated blocks) that name a host's id or configuration directory as a
/// string (`"copilot-cli"`, `".copilot"`). The list only shrinks, as
/// [`ALLOWED`] does.
const ALLOWED_NAMES: &[(&str, usize)] = &[
    // A test record's host.
    ("openmoat-cli/src/approvals/asked.rs", 1),
    // Inline tests of each host's MCP reader.
    ("openmoat-cli/src/mcp/servers.rs", 5),
    // A test record's host.
    ("openmoat-cli/src/protection.rs", 1),
    // The sandbox backends, which stay in the CLI, and their inline tests.
    ("openmoat-cli/src/sandbox/claude.rs", 1),
    ("openmoat-cli/src/sandbox/codex/names.rs", 1),
    ("openmoat-cli/src/sandbox/codex/own_binary.rs", 1),
    ("openmoat-cli/src/sandbox/hook_only.rs", 2),
    ("openmoat-cli/src/sandbox/patterns.rs", 1),
    // The download tools' `--continue` option, not the host.
    ("openmoat-core/src/shell/commands/fetch.rs", 1),
    ("openmoat-core/src/shell/options/transfer.rs", 1),
];

/// Each host's id and configuration directory names, quoted as in source.
fn quoted_names() -> Vec<String> {
    let mut names = Vec::new();
    for host in Host::EVERY {
        let spec = host.spec();
        names.push(spec.id);
        let dirs = spec.install.as_ref().map(|i| i.dir_name);
        for dir in dirs
            .into_iter()
            .chain(spec.detect.as_ref().map(|d| d.dir_name))
        {
            names.push(dir);
            // `.pi` for `.pi/agent`
            names.extend(dir.split_once('/').map(|(first, _)| first));
        }
    }
    names.sort_unstable();
    names.dedup();
    names.into_iter().map(|n| format!("\"{n}\"")).collect()
}

#[test]
fn only_host_modules_name_a_hosts_id_or_directory() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for root in ["openmoat-cli/src", "openmoat-core/src"] {
        rust_files(&crates.join(root), &mut files);
    }
    let names = quoted_names();
    assert!(names.contains(&"\".copilot\"".to_owned()), "{names:?}");
    let mut found = BTreeMap::new();
    for file in files {
        let relative = file
            .strip_prefix(&crates)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if relative.ends_with("/tests.rs") || relative.contains("/tests/") {
            continue;
        }
        let mut generated = false;
        let mut lines = 0;
        for line in fs::read_to_string(&file).unwrap().lines() {
            let comment = line.trim_start();
            if comment.starts_with("// generated:") {
                generated = true;
            } else if comment.starts_with("// /generated") {
                generated = false;
            } else if !generated && names.iter().any(|name| line.contains(name.as_str())) {
                lines += 1;
            }
        }
        if lines > 0 {
            found.insert(relative, lines);
        }
    }
    let allowed: BTreeMap<String, usize> = ALLOWED_NAMES
        .iter()
        .map(|(file, lines)| ((*file).to_owned(), *lines))
        .collect();
    for (file, lines) in &found {
        let limit = allowed.get(file).copied().unwrap_or(0);
        assert!(
            *lines <= limit,
            "{file} names a host's id or directory on {lines} lines (allowed {limit}): \
             take it from the host's spec"
        );
    }
    for (file, limit) in &allowed {
        let lines = found.get(file).copied().unwrap_or(0);
        assert_eq!(
            lines, *limit,
            "{file} now names a host's id or directory on {lines} lines: lower its entry \
             in ALLOWED_NAMES"
        );
    }
}

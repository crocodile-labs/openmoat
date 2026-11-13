//! Nothing outside a host's own module under `openmoat-hosts/src/host/` should
//! name a host: what differs between hosts belongs in its `HostSpec` or its
//! adapter. No `Host::<Variant>` is left outside them; the code that still
//! names a host's module is listed below, and the code, tests, scripts and
//! policy lines that name a host by a fact of its spec (`names.rs`) are listed
//! in `allowed.rs`, each with how many lines do. Those lists only shrink. A
//! file that names a host on fewer lines than listed fails too, so a list is
//! lowered with the change that fixes it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::Host;

mod allowed;
mod facts;
mod literals;
mod names;
#[path = "../common/policy_blocks.rs"]
mod policy_blocks;

/// What a scan found: each file, relative to the scan's root, and the lines
/// of it that name a host, described.
type Found = BTreeMap<String, Vec<String>>;

/// Every crate's sources, relative to `crates/`.
const SOURCE_ROOTS: &[&str] = &[
    "openmoat-audit/src",
    "openmoat-cli/src",
    "openmoat-core/src",
    "openmoat-hosts/src",
    "openmoat-proxy/src",
    "openmoat-sdk/src",
    "openmoat-wasm/src",
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
    for root in SOURCE_ROOTS {
        rust_files(&crates.join(root), &mut files);
    }
    assert!(files.len() > 100, "the scan found too little: {files:?}");
    let variants = variants();
    assert!(names_a_host(&format!("x({})", variants[0]), &variants));
    let mut found = BTreeMap::new();
    for file in files {
        let relative = relative_to(&file, &crates);
        if is_host_or_test_file(&relative) {
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
    assert_eq!(
        found,
        BTreeMap::new(),
        "these files name a host: move what differs into the host's spec or adapter"
    );
}

fn relative_to(file: &Path, crates: &Path) -> String {
    file.strip_prefix(crates)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

/// Whether `relative` is below a host's own module, or a test file.
fn is_host_or_test_file(relative: &str) -> bool {
    relative.starts_with("openmoat-hosts/src/host/")
        || relative.ends_with("/tests.rs")
        || relative.contains("/tests/")
}

/// `found` against `allowed`: nothing over its count, no entry above what the
/// code now has. Every file that differs is reported at once.
fn check_only_shrinks(found: &Found, allowed: &[(&str, usize)], what: &str, list: &str) {
    let allowed: BTreeMap<&str, usize> = allowed.iter().copied().collect();
    let mut wrong = Vec::new();
    for (file, lines) in found {
        let limit = allowed.get(file.as_str()).copied().unwrap_or(0);
        if lines.len() > limit {
            wrong.push(format!(
                "{file} names {what} on {} lines (allowed {limit}): take it from the host's \
                 spec\n    {}",
                lines.len(),
                lines.join("\n    ")
            ));
        }
    }
    for (file, limit) in &allowed {
        let lines = found.get(*file).map_or(0, Vec::len);
        if lines < *limit {
            wrong.push(format!(
                "{file} now names {what} on {lines} lines: lower its entry in {list} to {lines}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Lines of every crate's source (relative to `crates/`, outside the host
/// modules and test files) with a module path or module declaration naming a
/// host (`openclaw::`, `mod codex;`). Only `openmoat-cli/src/sandbox/` and what
/// reaches its per-format backends is to stay; the list only shrinks.
const ALLOWED_MODULES: &[(&str, usize)] = &[
    // The per-format sandbox backends and the plan that holds one output each
    // ([`openmoat_hosts::SandboxFormat`]), which stay in the CLI.
    ("openmoat-cli/src/sandbox.rs", 16),
    ("openmoat-cli/src/sandbox/backend.rs", 3),
    ("openmoat-cli/src/sandbox/codex/own_binary.rs", 1),
    ("openmoat-cli/src/sandbox/differential.rs", 1),
    ("openmoat-cli/src/sandbox/differential/hosts.rs", 2),
    ("openmoat-cli/src/sandbox/hook_only.rs", 4),
    // Re-exports the guard needs: Claude Code's `ConfigChange` helpers.
    ("openmoat-hosts/src/lib.rs", 2),
];

/// Each host's module name, and its first word for the short forms the CLI
/// uses (`claude` for `claude_code`).
fn module_names() -> Vec<String> {
    let mut names = Vec::new();
    for host in Host::EVERY {
        let module = host.module();
        names.push(module.to_owned());
        names.extend(module.split_once('_').map(|(first, _)| first.to_owned()));
    }
    names.sort_unstable();
    names.dedup();
    names
}

/// Whether `line` names `name` as a whole path segment (`x::name::y`, `name::y`,
/// not `other_name::`), or declares it as a module (`pub mod name;`).
fn names_module(line: &str, name: &str) -> bool {
    let starts_word = |at: usize| {
        !line[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    };
    let path = format!("{name}::");
    if line.match_indices(&path).any(|(at, _)| starts_word(at)) {
        return true;
    }
    let declared = format!("mod {name}");
    line.match_indices(&declared).any(|(at, _)| {
        starts_word(at)
            && line[at + declared.len()..]
                .chars()
                .next()
                .is_some_and(|c| c == ';' || c == ' ')
    })
}

#[test]
fn only_host_modules_name_a_hosts_module() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for root in SOURCE_ROOTS {
        rust_files(&crates.join(root), &mut files);
    }
    let names = module_names();
    assert!(names.contains(&"openclaw".to_owned()), "{names:?}");
    assert!(names.contains(&"claude".to_owned()), "{names:?}");
    assert!(names_module(
        "crate::install::openclaw::parse(x)",
        "openclaw"
    ));
    assert!(names_module("pub mod codex;", "codex"));
    assert!(!names_module("x::claude_version::y()", "claude"));
    let mut found = Found::new();
    for file in files {
        let relative = relative_to(&file, &crates);
        if is_host_or_test_file(&relative) {
            continue;
        }
        let lines: Vec<String> = fs::read_to_string(&file)
            .unwrap()
            .lines()
            .enumerate()
            .filter(|(_, l)| names.iter().any(|n| names_module(l, n)))
            .map(|(at, l)| format!("{}: {}", at + 1, l.trim()))
            .collect();
        if !lines.is_empty() {
            found.insert(relative, lines);
        }
    }
    check_only_shrinks(
        &found,
        ALLOWED_MODULES,
        "a host's module",
        "ALLOWED_MODULES",
    );
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

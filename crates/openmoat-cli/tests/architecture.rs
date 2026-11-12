//! Remote approval's channels (ADR-078, "Channel architecture"): a channel is
//! `src/remote/channels/<name>.rs` with its folder `src/remote/channels/<name>/`,
//! and one row in the registry, `src/remote/channels.rs`. Nothing else names a
//! channel, so adding one changes no core file. The allowlists below only
//! shrink: a file that names a channel on fewer lines than listed fails too,
//! so an entry is lowered with the change that fixes it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn channels_dir() -> PathBuf {
    src().join("remote").join("channels")
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

fn relative(file: &Path) -> String {
    file.strip_prefix(src())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every channel: the stem of each `channels/<name>.rs`.
fn channels() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(channels_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The registry's rows: what is between `Registry(&[` and `]);`.
fn registry_rows() -> Vec<String> {
    let text = fs::read_to_string(src().join("remote").join("channels.rs")).unwrap();
    let rows = text.split_once("Registry(&[").unwrap().1;
    let rows = rows.split_once("]);").unwrap().0;
    rows.split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty() && !r.starts_with("//"))
        .map(str::to_owned)
        .collect()
}

/// Every channel file has its row (`&<name>::SPEC`) and its `mod <name>;`, its
/// spec carries its own name, every folder has its file, and nothing else
/// lives under `channels/`.
#[test]
fn every_channel_folder_is_registered() {
    let names = channels();
    assert!(!names.is_empty(), "no channel found");
    let rows = registry_rows();
    let expected: Vec<String> = names.iter().map(|n| format!("&{n}::SPEC")).collect();
    assert_eq!(
        rows, expected,
        "one registry row per channel file, in file order"
    );
    let registry = fs::read_to_string(src().join("remote").join("channels.rs")).unwrap();
    for name in &names {
        assert!(
            registry.lines().any(|l| l.trim() == format!("mod {name};")),
            "channels.rs does not declare `mod {name};`"
        );
        let file = fs::read_to_string(channels_dir().join(format!("{name}.rs"))).unwrap();
        assert!(
            file.contains("pub const SPEC: Spec = Spec {")
                && file.contains(&format!("name: \"{name}\",")),
            "{name}.rs defines `pub const SPEC` with `name: \"{name}\"`"
        );
    }
    for entry in fs::read_dir(channels_dir()).unwrap() {
        let path = entry.unwrap().path();
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        // A file manager's hidden files (`.DS_Store`) are not source.
        if stem.starts_with('.') {
            continue;
        }
        assert!(
            names.contains(&stem),
            "{} is not a channel: a folder needs its `<name>.rs` and a registry row",
            path.display()
        );
    }
}

/// Lines of the core that name a channel (relative to `src/`). The core is
/// every file of remote approval outside `remote/channels/<name>.rs` and
/// `remote/channels/<name>/`, the registry, and the commands and grammar of
/// `openmoat approvals`. The list only shrinks; it starts empty.
const ALLOWED_IN_CORE: &[(&str, usize)] = &[];

/// The files the rule covers.
fn core_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    rust_files(&src().join("remote"), &mut files);
    // The channels and the registry are the only places that name one.
    let registry = src().join("remote").join("channels.rs");
    files.retain(|f| !f.starts_with(channels_dir()) && *f != registry);
    files.push(src().join("remote.rs"));
    files.push(src().join("commands").join("approvals.rs"));
    files.push(src().join("cli").join("approvals.rs"));
    files.sort();
    files
}

/// Whether `line` names `name` as a word, in any case (`telegram::x`,
/// `Telegram's`, `"telegram"`), not inside a longer word.
fn names_channel(line: &str, name: &str) -> bool {
    let line = line.to_ascii_lowercase();
    line.match_indices(name).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + name.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric())
            && !after.is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

#[test]
fn the_core_names_no_channel() {
    let names = channels();
    assert!(names_channel("use super::telegram::Spec;", "telegram"));
    assert!(names_channel("// Telegram's 64 bytes", "telegram"));
    assert!(!names_channel("telegrammar", "telegram"));
    let files = core_files();
    assert!(files.len() >= 10, "the scan found too little: {files:?}");
    let mut found = BTreeMap::new();
    for file in files {
        let lines = fs::read_to_string(&file)
            .unwrap()
            .lines()
            .filter(|l| names.iter().any(|n| names_channel(l, n)))
            .count();
        if lines > 0 {
            found.insert(relative(&file), lines);
        }
    }
    check_only_shrinks(&found, ALLOWED_IN_CORE, "ALLOWED_IN_CORE");
}

/// Outside `remote/`, no code reaches into a channel's module: everything
/// goes through the registry.
#[test]
fn only_the_registry_reaches_a_channel_module() {
    let names = channels();
    let mut files = Vec::new();
    rust_files(&src(), &mut files);
    let mut offenders = Vec::new();
    for file in files {
        if file.starts_with(channels_dir()) || file == src().join("remote").join("channels.rs") {
            continue;
        }
        let text = fs::read_to_string(&file).unwrap();
        for name in &names {
            if text.contains(&format!("{name}::")) || text.contains(&format!("mod {name};")) {
                offenders.push(format!("{} reaches channels::{name}", relative(&file)));
            }
        }
    }
    assert_eq!(offenders, Vec::<String>::new());
}

/// Only a channel does network I/O: no core file uses the HTTPS transport.
#[test]
fn only_channels_use_the_network() {
    let mut offenders = Vec::new();
    for file in core_files() {
        let rel = relative(&file);
        if rel == "remote/https.rs" {
            continue;
        }
        let text = fs::read_to_string(&file).unwrap();
        if text.contains("https::")
            || text.contains("TcpStream")
            || text.contains("UdpSocket")
            || text.contains("rustls")
        {
            offenders.push(rel);
        }
    }
    assert_eq!(offenders, Vec::<String>::new());
}

/// `found` against `allowed`: nothing over its count, no entry above what the
/// code now has.
fn check_only_shrinks(found: &BTreeMap<String, usize>, allowed: &[(&str, usize)], list: &str) {
    let allowed: BTreeMap<String, usize> = allowed
        .iter()
        .map(|(file, lines)| ((*file).to_owned(), *lines))
        .collect();
    for (file, lines) in found {
        let limit = allowed.get(file).copied().unwrap_or(0);
        assert!(
            *lines <= limit,
            "{file} names a channel on {lines} lines (allowed {limit}): take it from the \
             channel's spec or move it into the channel's folder"
        );
    }
    for (file, limit) in &allowed {
        let lines = found.get(file).copied().unwrap_or(0);
        assert_eq!(
            lines, *limit,
            "{file} now names a channel on {lines} lines: lower its entry in {list}"
        );
    }
}

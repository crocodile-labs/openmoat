//! Architecture invariants for the trusted core (`docs/ARCHITECTURE.md` §1).
//!
//! `openmoat-core` must stay pure: no internal crates, no I/O or runtime crates.
//! The wasm32 build in CI catches most OS calls; `std::fs`/`std::env` still
//! compile there, so the source scan below is what actually enforces purity.

use std::fs;
use std::path::Path;

const ALLOWED_DEPENDENCIES: &[&str] = &["serde", "serde-saphyr", "globset", "thiserror"];

#[test]
fn core_depends_only_on_pure_crates() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = fs::read_to_string(&manifest).unwrap();
    let deps = section(&text, "[dependencies]");
    for name in deps {
        assert!(
            ALLOWED_DEPENDENCIES.contains(&name.as_str()),
            "openmoat-core gained dependency `{name}`; the core must stay free of I/O and internal crates"
        );
    }
}

#[test]
fn core_forbids_unsafe() {
    let lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let combined = fs::read_to_string(lib).unwrap() + &fs::read_to_string(root).unwrap();
    assert!(
        combined.contains("unsafe_code = \"forbid\"") || combined.contains("forbid(unsafe_code)"),
        "unsafe must be forbidden for openmoat-core"
    );
}

/// AGENTS §4: no file in any crate, sources or tests, exceeds 500 lines.
#[test]
fn no_file_in_any_crate_exceeds_the_size_budget() {
    const MAX_LINES: usize = 500;
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut offenders = Vec::new();
    for entry in fs::read_dir(&crates).unwrap() {
        let krate = entry.unwrap().path();
        for dir in ["src", "tests"] {
            let root = krate.join(dir);
            if !root.is_dir() {
                continue;
            }
            visit(&root, &mut |path| {
                let lines = fs::read_to_string(path).unwrap().lines().count();
                if lines > MAX_LINES {
                    offenders.push(format!("{} ({lines} lines)", path.display()));
                }
            });
        }
    }
    assert!(
        offenders.is_empty(),
        "split these files:\n{}",
        offenders.join("\n")
    );
}

/// AGENTS §4: a module with children is `foo.rs` + `foo/`, never `foo/mod.rs`,
/// and no module is wired to a file through a `path` attribute.
#[test]
fn modules_use_one_file_style() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut offenders = Vec::new();
    for entry in fs::read_dir(&crates).unwrap() {
        let krate = entry.unwrap().path();
        for dir in ["src", "tests"] {
            let root = krate.join(dir);
            if !root.is_dir() {
                continue;
            }
            visit(&root, &mut |path| {
                if path.file_name().is_some_and(|n| n == "mod.rs") {
                    offenders.push(format!("{} is a mod.rs", path.display()));
                }
                for (n, line) in fs::read_to_string(path).unwrap().lines().enumerate() {
                    let code = line.trim_start();
                    // `path = "…"` alone on a line is a multi-line `cfg_attr`.
                    if code.starts_with("#[path")
                        || code.starts_with("path = \"")
                        || (code.starts_with("#[cfg_attr(") && code.contains("path = \""))
                    {
                        offenders.push(format!("{}:{} sets a module path", path.display(), n + 1));
                    }
                }
            });
        }
    }
    assert!(
        offenders.is_empty(),
        "use `foo.rs` + `foo/` and `cfg` on the `mod` line:\n{}",
        offenders.join("\n")
    );
}

const FORBIDDEN_IN_CORE: &[&str] = &[
    "std::fs",
    "std::env",
    "std::process",
    "std::net",
    "std::io::std",
    "println!",
    "eprintln!",
    "dbg!",
];

#[test]
fn core_sources_do_no_io() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    visit(&src, &mut |path| {
        for (n, line) in fs::read_to_string(path).unwrap().lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if let Some(hit) = FORBIDDEN_IN_CORE.iter().find(|t| code.contains(*t)) {
                offenders.push(format!("{}:{} uses {hit}", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "openmoat-core must stay free of I/O; inject it from the CLI through a trait:\n{}",
        offenders.join("\n")
    );
}

fn section(toml: &str, header: &str) -> Vec<String> {
    toml.lines()
        .skip_while(|l| l.trim() != header)
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .filter_map(|l| {
            let key = l.split(['=', '.']).next()?.trim();
            (!key.is_empty() && !key.starts_with('#')).then(|| key.to_owned())
        })
        .collect()
}

fn visit(dir: &Path, f: &mut dyn FnMut(&Path)) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            visit(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            f(&path);
        }
    }
}

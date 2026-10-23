//! The lists of host paths outside this crate that a [`Protect`] states are
//! generated from each host's spec, so a host's paths are written once:
//!
//! - the default policy's `kernel-self` paths of the hosts that list theirs
//!   apart. The policy's bytes are pinned (a lock pins its hash, and
//!   `openmoat policy upgrade` merges it line by line), so it carries no
//!   markers: the block is the lines between two lines that are there anyway.
//! - the core's taint list (`PROTECTED_WRITES`), between `// generated:taint`
//!   and `// /generated`.
//!
//! Claude Code's, Codex's and Cursor's paths stay hand-written: those lists
//! name them among each other's and OpenMoat's own lines.
//!
//! Regenerate with `OPENMOAT_TEST_UPDATE_PROTECT=1 cargo test -p openmoat-hosts --test protect`.

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, Paths, Protect};

const UPDATE: &str = "OPENMOAT_TEST_UPDATE_PROTECT";

const POLICY: &str = "crates/openmoat-core/policies/default-v1.yaml";
/// The `kernel-self` lines just before and just after the generated block.
const POLICY_BEFORE: &str = "      - \"**/.codex/hooks.json\"\n";
const POLICY_AFTER: &str = "      - \"**/.moat/**\"\n";

const TAINT: &str = "crates/openmoat-core/src/taint.rs";
const TAINT_BEFORE: &str = "// generated:taint ";
const TAINT_AFTER: &str = "    // /generated\n";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Each host's `pick` lists, in the host list's order: every comment line as
/// `comment` makes it, every glob as `glob` does.
fn lines(
    pick: fn(&Protect) -> &[Paths],
    comment: fn(&str) -> String,
    glob: fn(&str) -> String,
) -> String {
    let mut out = String::new();
    for host in Host::EVERY {
        for paths in pick(&host.spec().protect) {
            for line in paths.why.lines() {
                out.push_str(&comment(line));
                out.push('\n');
            }
            for g in paths.globs {
                out.push_str(&glob(g));
                out.push('\n');
            }
        }
    }
    out
}

/// `text` with what lies between the line ending in `before` and the line
/// `after` that follows it replaced by `body`.
fn splice(text: &str, before: &str, after: &str, body: &str) -> Result<String, String> {
    let mut found = text.match_indices(before);
    let (at, _) = found.next().ok_or(format!("no `{before}`"))?;
    if found.next().is_some() {
        return Err(format!("`{before}` appears twice"));
    }
    let start = at + text[at..].find('\n').ok_or("no line after the start")? + 1;
    let end = start
        + text[start..]
            .find(after)
            .ok_or(format!("no `{after}` after `{before}`"))?;
    Ok(format!("{}{body}{}", &text[..start], &text[end..]))
}

fn check(file: &str, before: &str, after: &str, body: &str) {
    let path = repo_root().join(file);
    let current = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
    let want = splice(&current, before, after, body).unwrap();
    if std::env::var_os(UPDATE).is_some() && want != current {
        fs::write(&path, &want).unwrap();
        return;
    }
    assert!(
        want == current,
        "{file} differs from the host specs' paths; regenerate with \
         `{UPDATE}=1 cargo test -p openmoat-hosts --test protect`"
    );
}

#[test]
fn the_default_policy_protects_each_hosts_own_files() {
    let body = lines(
        |p| p.self_paths,
        |line| format!("      # {line}"),
        |glob| format!("      - \"{glob}\""),
    );
    assert!(body.contains("~/.copilot/hooks/**"), "{body}");
    check(POLICY, POLICY_BEFORE, POLICY_AFTER, &body);
}

#[test]
fn the_taint_list_protects_each_hosts_own_files() {
    let body = lines(
        |p| p.taint,
        |line| format!("    // {line}"),
        |glob| format!("    \"{glob}\","),
    );
    assert!(body.contains("**/.copilot/hooks/**"), "{body}");
    check(TAINT, TAINT_BEFORE, TAINT_AFTER, &body);
}

#[test]
fn splice_replaces_only_the_lines_between() {
    let text = "a\nstart x\nold\nold\nend\nz\n";
    assert_eq!(
        splice(text, "start", "end\n", "new\n").unwrap(),
        "a\nstart x\nnew\nend\nz\n"
    );
    assert!(splice("start\nstart\nend\n", "start", "end\n", "").is_err());
    assert!(splice("start\nx\n", "start", "end\n", "").is_err());
}

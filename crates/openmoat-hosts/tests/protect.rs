//! The lists of host paths outside this crate that a [`Protect`] states are
//! generated from each host's spec, so a host's paths are written once:
//!
//! - the default policy's `kernel-self` paths of the hosts that list theirs
//!   apart. The policy's bytes are pinned (a lock pins its hash, and
//!   `openmoat policy upgrade` merges it line by line), so it carries no
//!   markers: the block is the lines between two lines that are there anyway.
//! - the default policy's `agent-credentials` paths of every host, between the
//!   rule's `fs.read` anchor and its `fs.write` alias.
//! - the core's taint list (`PROTECTED_WRITES`), between `// generated:taint`
//!   and `// /generated`.
//!
//! Claude Code's, Codex's and Cursor's `kernel-self` and taint paths stay
//! hand-written: those lists name them among each other's and OpenMoat's own
//! lines.
//!
//! Regenerate with `OPENMOAT_TEST_UPDATE_PROTECT=1 cargo test -p openmoat-hosts --test protect`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, Paths, Protect};

const UPDATE: &str = "OPENMOAT_TEST_UPDATE_PROTECT";

const POLICY: &str = "crates/openmoat-core/policies/default-v1.yaml";
/// The `kernel-self` lines just before and just after the generated block.
const POLICY_BEFORE: &str = "      - \"**/.codex/hooks.json\"\n";
const POLICY_AFTER: &str = "      - \"**/.moat/**\"\n";
/// The `agent-credentials` lines just before and just after its paths.
const CREDENTIALS_BEFORE: &str = "    fs.read: &agent-credentials\n";
const CREDENTIALS_AFTER: &str = "    fs.write: *agent-credentials\n";

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

/// The credential paths of each host's `Paths` as few globs as they fit in:
/// the paths under one directory of the home (`~/.hermes`, `~/.config`) as one
/// brace group, `dir/**` with `dir` itself as the whole pattern's `/**`
/// would. A guard compiles a glob the first time a path is checked against
/// it, so one glob per file would add that cost to every call naming a path;
/// the directory stays the pattern's start, so a moved agent directory is
/// still followed.
fn credential_lines() -> String {
    let mut out = String::new();
    for host in Host::EVERY {
        for paths in host.spec().protect.credentials {
            for line in paths.why.lines() {
                let _ = writeln!(out, "      # {line}");
            }
            let mut groups: Vec<(&str, Vec<String>)> = Vec::new();
            for glob in paths.globs {
                let (root, rest) = split_root(glob);
                let mut items = vec![rest.to_owned()];
                if let Some(dir) = rest.strip_suffix("/**") {
                    items.insert(0, dir.to_owned());
                }
                match groups.iter_mut().find(|(r, _)| *r == root) {
                    Some((_, list)) => list.extend(items),
                    None => groups.push((root, items)),
                }
            }
            for (root, items) in groups {
                // The folders every item shares join the start (`~/.pi/agent/`,
                // the directory a variable moves), so the pattern keeps it.
                let (shared, items) = shared_dirs(&items);
                let root = format!("{root}{shared}");
                let glob = match items.as_slice() {
                    [one] => format!("{root}{one}"),
                    _ => format!("{root}{{{}}}", items.join(",")),
                };
                let _ = writeln!(out, "      - \"{glob}\"");
            }
        }
    }
    out
}

/// `~/.hermes/auth.json` as `("~/.hermes/", "auth.json")`: the home and the
/// directory in it, and the rest.
fn split_root(glob: &str) -> (&str, &str) {
    let skip = if glob.starts_with("~/") { 2 } else { 0 };
    match glob[skip..].find('/') {
        Some(at) => glob.split_at(skip + at + 1),
        None => (glob, ""),
    }
}

/// The leading folders (no glob syntax) every one of `items` has, as
/// `"a/b/"`, and the items without them; never all of an item.
fn shared_dirs(items: &[String]) -> (String, Vec<String>) {
    let split: Vec<Vec<&str>> = items.iter().map(|i| i.split('/').collect()).collect();
    let mut n = 0;
    while split.iter().all(|parts| {
        parts.len() > n + 1 && !parts[n].contains(['*', '?', '[', '{']) && parts[n] == split[0][n]
    }) {
        n += 1;
    }
    let shared: String = split[0][..n].iter().flat_map(|p| [*p, "/"]).collect();
    let rest = split.iter().map(|parts| parts[n..].join("/")).collect();
    (shared, rest)
}

#[test]
fn credential_globs_group_by_directory() {
    assert_eq!(
        split_root("~/.hermes/auth.json"),
        ("~/.hermes/", "auth.json")
    );
    assert_eq!(split_root("~/.netrc"), ("~/.netrc", ""));
    let items = ["agent/auth.json".to_owned(), "agent/mcp/x.json".to_owned()];
    assert_eq!(
        shared_dirs(&items),
        (
            "agent/".to_owned(),
            vec!["auth.json".to_owned(), "mcp/x.json".to_owned()]
        )
    );
    // `dir` beside `dir/**` keeps nothing shared past `dir`'s parent.
    let items = ["mcp".to_owned(), "mcp/**".to_owned()];
    assert_eq!(shared_dirs(&items).0, "");
}

#[test]
fn the_default_policy_keeps_each_agents_credentials_from_its_tools() {
    let body = credential_lines();
    // Every host OpenMoat sets up names where it keeps a login, except
    // Cursor, whose store is not documented.
    let without: Vec<&str> = Host::ALL
        .into_iter()
        .filter(|h| h.spec().protect.credentials.is_empty())
        .map(Host::display_name)
        .collect();
    assert_eq!(without, ["Cursor"]);
    assert!(
        body.contains("~/.local/share/opencode/{auth.json,"),
        "{body}"
    );
    assert!(body.contains("~/.pi/agent/{auth.json,"), "{body}");
    check(POLICY, CREDENTIALS_BEFORE, CREDENTIALS_AFTER, &body);
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

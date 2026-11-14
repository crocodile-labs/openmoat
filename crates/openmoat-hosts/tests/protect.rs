//! The lists of host paths outside this crate that a [`Protect`] states are
//! generated from each host's spec, so a host's paths are written once:
//!
//! - the default policy's `kernel-self` paths of the hosts that list theirs
//!   apart. The policy's bytes are pinned (a lock pins its hash, and
//!   `openmoat policy upgrade` merges it line by line), so it carries no
//!   markers: the block is the lines between two lines that are there anyway.
//! - the default policy's `agent-credentials` paths of every host, between the
//!   rule's `fs.read` anchor and its `fs.write` alias.
//! - the default policy's `runs-later` paths of every host, and `project-fs`'s
//!   `!${project}/…` exceptions for the ones in a project, each between a
//!   comment line naming the specs and the comment of the hand-written paths
//!   that follow (CI, editors, builds, Python, virtual environments, dev
//!   containers: files no host owns). The CLI's sandboxes read the same specs
//!   (`RUNS_LATER`, `AGENT_CONFIG` in `crates/openmoat-cli/src/sandbox/patterns.rs`).
//! - the default policy's `agent-temp` reads, each host's temporary folders
//!   ([`Protect::temp_dirs`]), which the core's staging also reads, and
//!   `managed-settings`' writes, the folders of each host's system-wide
//!   settings files ([`openmoat_hosts::HostSpec::system_settings`]).
//! - the core's taint list (`PROTECTED_WRITES`), between `// generated:taint`
//!   and `// /generated`, and its built-in metadata tools
//!   (`BUILTIN_METADATA_TOOLS`, from [`openmoat_hosts::HostSpec::builtin_mcp`]).
//!
//! Claude Code's, Codex's and Cursor's `kernel-self` paths stay hand-written:
//! that list names them among each other's and OpenMoat's own lines.
//!
//! Regenerate with `OPENMOAT_TEST_UPDATE_PROTECT=1 cargo test -p openmoat-hosts --test protect`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use openmoat_hosts::{Host, Paths, Protect};

mod policy_blocks {
    include!("common/policy_blocks.rs");
}
use policy_blocks::{
    AGENT_TEMP_AFTER, AGENT_TEMP_BEFORE, BLOCKS, CORE_AFTER, CREDENTIALS_AFTER, CREDENTIALS_BEFORE,
    MANAGED_AFTER, MANAGED_BEFORE, METADATA_BEFORE, POLICY, POLICY_AFTER, POLICY_BEFORE,
    PROJECT_FS_AFTER, PROJECT_FS_BEFORE, RUNS_LATER_AFTER, RUNS_LATER_BEFORE, TAINT, TAINT_BEFORE,
};

const UPDATE: &str = "OPENMOAT_TEST_UPDATE_PROTECT";

/// The widest a generated line of quoted globs gets, as `cargo fmt` keeps code.
const WIDTH: usize = 100;

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

/// Held while a test reads and rewrites a generated file: four tests splice
/// blocks into the one default policy, and run in parallel, one's write would
/// drop another's.
static FILES: Mutex<()> = Mutex::new(());

fn check(file: &str, before: &str, after: &str, body: &str) {
    // another test failing while it held the lock does not stop this one
    let _held = FILES.lock().unwrap_or_else(PoisonError::into_inner);
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
    check(TAINT, TAINT_BEFORE, CORE_AFTER, &body);
}

/// The core's built-in metadata tools: each host's [`openmoat_hosts::BuiltinMcp`],
/// its comment, then one `(server, tool)` a line.
#[test]
fn the_core_lists_each_hosts_builtin_metadata_tools() {
    let mut body = String::new();
    for host in Host::EVERY {
        let Some(builtin) = &host.spec().builtin_mcp else {
            continue;
        };
        for line in builtin.why.lines() {
            let _ = writeln!(body, "    // {line}");
        }
        for tool in builtin.metadata_tools {
            let _ = writeln!(body, "    (\"{}\", \"{tool}\"),", builtin.server);
        }
    }
    assert!(body.contains("\"tabs_context_mcp\""), "{body}");
    check(TAINT, METADATA_BEFORE, CORE_AFTER, &body);
}

/// The `agent-temp` rule's reads: each host's [`Protect::temp_dirs`].
#[test]
fn the_default_policy_lets_each_host_read_its_temporary_folders() {
    let body = lines(
        |p| p.temp_dirs,
        |line| format!("      # {line}"),
        |glob| format!("      - \"{glob}\""),
    );
    assert!(body.contains("/tmp/claude-*/**"), "{body}");
    check(POLICY, AGENT_TEMP_BEFORE, AGENT_TEMP_AFTER, &body);
}

/// The `managed-settings` rule's writes: the folder of each system-wide
/// settings file a host reads (its drop-ins sit beside it), each folder once,
/// under the host's name.
fn managed_settings_lines() -> String {
    let mut out = String::new();
    for host in Host::EVERY {
        let Some(system) = &host.spec().system_settings else {
            continue;
        };
        let mut folders: Vec<&str> = Vec::new();
        for file in system.files {
            let (folder, _) = file.path.rsplit_once('/').unwrap();
            if !folders.contains(&folder) {
                folders.push(folder);
            }
        }
        let _ = writeln!(out, "      # {}", host.display_name());
        for folder in folders {
            let _ = writeln!(out, "      - \"{folder}/**\"");
        }
    }
    out
}

#[test]
fn the_default_policy_keeps_each_hosts_system_settings_from_its_tools() {
    let body = managed_settings_lines();
    assert!(body.contains("\"/etc/codex/**\""), "{body}");
    check(POLICY, MANAGED_BEFORE, MANAGED_AFTER, &body);
}

/// `items` quoted, comma-separated and packed into lines of at most [`WIDTH`]
/// columns (one item a line when it is wider), each line indented by six
/// spaces and ending in a comma.
fn packed(items: &[String]) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for item in items {
        let quoted = format!("\"{item}\",");
        if !line.is_empty() && 6 + line.len() + 1 + quoted.len() > WIDTH {
            let _ = writeln!(out, "      {line}");
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&quoted);
    }
    if !line.is_empty() {
        let _ = writeln!(out, "      {line}");
    }
    out
}

/// The `runs-later` rule's lines for every host's [`Protect::runs_later`]:
/// each entry's comment, then its globs.
fn runs_later_lines() -> String {
    let mut out = String::new();
    for host in Host::EVERY {
        for entry in host.spec().protect.runs_later {
            for line in entry.paths.why.lines() {
                let _ = writeln!(out, "      # {line}");
            }
            let globs: Vec<String> = entry.paths.globs.iter().map(|g| (*g).to_owned()).collect();
            out.push_str(&packed(&globs));
        }
    }
    out
}

/// `project-fs`'s exceptions for every host's project globs (`**/…`) among
/// its [`Protect::runs_later`], one group a host.
fn project_fs_lines() -> String {
    let mut out = String::new();
    for host in Host::EVERY {
        let excepted: Vec<String> = host
            .spec()
            .protect
            .runs_later
            .iter()
            .flat_map(|entry| entry.paths.globs)
            .filter(|g| g.starts_with("**/"))
            .map(|g| format!("!${{project}}/{g}"))
            .collect();
        if !excepted.is_empty() {
            let _ = writeln!(out, "      # {}", host.display_name());
            out.push_str(&packed(&excepted));
        }
    }
    out
}

#[test]
fn the_default_policy_holds_each_hosts_files_that_run_later_for_review() {
    let body = runs_later_lines();
    assert!(body.contains("\"**/.cline/hooks/**\""), "{body}");
    assert!(body.contains("\"~/.claude.json\""), "{body}");
    check(POLICY, RUNS_LATER_BEFORE, RUNS_LATER_AFTER, &body);
}

#[test]
fn project_fs_leaves_out_each_hosts_files_that_run_later() {
    let body = project_fs_lines();
    assert!(
        body.contains("\"!${project}/**/.gemini/commands/**\""),
        "{body}"
    );
    assert!(!body.contains("~/"), "{body}");
    check(POLICY, PROJECT_FS_BEFORE, PROJECT_FS_AFTER, &body);
}

/// An entry marked as the host's configuration names files in a project, as
/// `**/<folder>/…` or `**/<file>`: the sandboxes of `openmoat run` match it below
/// the project and deny the folders above it, which need no glob of their own.
#[test]
fn agent_configuration_is_named_in_the_project() {
    let mut found = 0;
    for host in Host::EVERY {
        for entry in host.spec().protect.runs_later {
            for glob in entry.paths.globs {
                let rest = glob.strip_prefix("**/");
                if entry.agent_config {
                    found += 1;
                    let rest = rest.unwrap_or_else(|| panic!("{host:?}: {glob} is not `**/…`"));
                    let name = rest.strip_suffix("/**").unwrap_or(rest);
                    assert!(
                        !name.contains(['*', '?', '[', '{']),
                        "{host:?}: {glob} has a glob below `**/`"
                    );
                } else if let Some(rest) = rest {
                    // a project path held for review only is a folder above an
                    // entry of the host's configuration, or a file the host
                    // writes itself in such a folder (OpenCode's
                    // `.opencode/package.json`), which `openmoat run` must
                    // leave writable to the host
                    let holds = |folder: &str| {
                        host.spec().protect.runs_later.iter().any(|e| {
                            e.agent_config
                                && e.paths
                                    .globs
                                    .iter()
                                    .any(|g| g.starts_with(&format!("**/{folder}/")))
                        })
                    };
                    let beside = rest
                        .rsplit_once('/')
                        .is_some_and(|(folder, name)| holds(folder) && !name.contains('*'));
                    assert!(
                        holds(rest) || beside,
                        "{host:?}: {glob} is neither above nor beside its configuration"
                    );
                } else {
                    assert!(glob.starts_with("~/"), "{host:?}: {glob}");
                }
            }
        }
    }
    assert!(found > 0);
}

#[test]
fn packed_lines_stay_narrow() {
    let items: Vec<String> = (0..30).map(|i| format!("**/.agent{i}/x/**")).collect();
    let text = packed(&items);
    assert!(text.lines().count() > 1, "{text}");
    for line in text.lines() {
        assert!(line.len() <= WIDTH && line.ends_with(','), "{line}");
    }
    assert_eq!(packed(&[]), "");
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

/// Each generated block of the default policy lies between its two lines,
/// each found once: the architecture test leaves exactly these blocks out.
#[test]
fn every_policy_block_has_its_two_lines_once() {
    let text = fs::read_to_string(repo_root().join(POLICY))
        .unwrap()
        .replace("\r\n", "\n");
    for (before, after) in BLOCKS {
        assert_eq!(text.matches(before).count(), 1, "{before:?}");
        let at = text.find(before).unwrap();
        assert!(text[at..].contains(after), "{after:?} after {before:?}");
    }
}

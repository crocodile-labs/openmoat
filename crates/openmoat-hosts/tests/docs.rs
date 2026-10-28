//! The host tables in the docs that a [`HostSpec`] fully states are generated
//! from it, between `<!-- generated:<name> -->` and `<!-- /generated -->`, so a
//! spec change and its documentation cannot drift apart. Tables that need more
//! than the spec says (what each hook sees, the per-case "When the hook fails"
//! table) stay hand-written.
//!
//! Regenerate with `OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test docs`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::{Host, HostSpec};

const END: &str = "<!-- /generated -->";
const UPDATE: &str = "OPENMOAT_TEST_UPDATE_DOCS";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every host, in the order the docs list them: the installable ones, then
/// those that run another's hook.
fn hosts() -> Vec<Host> {
    let rest = Host::EVERY.into_iter().filter(|h| !Host::ALL.contains(h));
    Host::ALL.into_iter().chain(rest).collect()
}

/// `docs/INSTALL.md` "Non-default config directories": where each agent keeps
/// the file `moat init` writes its hook into, and the entries it writes.
fn install_table() -> Vec<String> {
    let mut lines = vec![
        "| Agent | Directory | Moved by | Hook file | Entries `openmoat init` writes |".to_owned(),
        "|---|---|---|---|---|".to_owned(),
    ];
    for host in Host::ALL {
        let spec = host.spec();
        let install = spec.install.as_ref().unwrap();
        let entries = install
            .hooks
            .iter()
            .map(|hook| format!("`{}` ({} s)", hook.event, hook.timeout))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "| {} | `~/{}` | `{}` | `{}` | {entries} |",
            spec.display_name, install.dir_name, install.dir_variable, install.config_file
        ));
    }
    lines
}

/// `docs/THREAT_MODEL.md` §5: what `moat status` and `moat doctor` print as each
/// agent's known gaps, and what the agent does when its hook fails.
fn gaps_list() -> Vec<String> {
    hosts()
        .iter()
        .map(|host| {
            let spec = host.spec();
            format!(
                "- **{}.** Known gaps: {}. When the hook fails: {}.",
                spec.display_name, spec.gaps, spec.on_hook_failure
            )
        })
        .collect()
}

/// `README.md` "Supported agents": how each agent is hooked, what checks its
/// calls, and its `--hosts` id (none for an agent with no hook to install).
fn agents_table() -> Vec<String> {
    let mut lines = vec![
        "| Agent | How OpenMoat is hooked | Protection | `openmoat init --hosts` |".to_owned(),
        "|---|---|---|---|".to_owned(),
    ];
    for host in hosts() {
        let spec = host.spec();
        let id = match spec.install {
            Some(_) => format!("`{}`", spec.id),
            None => "none".to_owned(),
        };
        lines.push(format!(
            "| {} | {} | {} | {id} |",
            spec.display_name, spec.docs.hooked_by, spec.docs.protection
        ));
    }
    lines
}

/// `docs/ARCHITECTURE.md` §3 "Host tool mapping": each agent's rows.
fn tools_table() -> Vec<String> {
    let mut lines = vec![
        "| Agent | Host tool | Field read | Action |".to_owned(),
        "|---|---|---|---|".to_owned(),
    ];
    for host in Host::ALL {
        let spec = host.spec();
        for row in spec.docs.tools {
            lines.push(format!(
                "| {} | {} | {} | {} |",
                spec.display_name, row.tool, row.reads, row.action
            ));
        }
    }
    lines
}

/// `text` with the block named `name` replaced by `body`, each line indented
/// as the opening marker is.
fn splice(text: &str, name: &str, body: &[String]) -> Result<String, String> {
    let start = format!("<!-- generated:{name} -->");
    let mut found = text.match_indices(&start);
    let (at, _) = found.next().ok_or(format!("no `{start}`"))?;
    if found.next().is_some() {
        return Err(format!("`{start}` appears twice"));
    }
    let open_end = at + start.len();
    let close = open_end
        + text[open_end..]
            .find(END)
            .ok_or(format!("`{start}` has no `{END}`"))?;
    let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    let indent = &text[line_start..at];
    let mut between = String::from("\n");
    for line in body {
        let _ = writeln!(between, "{indent}{line}");
    }
    between.push_str(indent);
    Ok(format!("{}{between}{}", &text[..open_end], &text[close..]))
}

/// Each generated block of `file` matches what the specs say now.
fn check(file: &str, blocks: &[(&str, Vec<String>)]) {
    let path = repo_root().join(file);
    let current = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
    let mut want = current.clone();
    for (name, body) in blocks {
        want = splice(&want, name, body).unwrap_or_else(|e| panic!("{file}: {e}"));
    }
    if std::env::var_os(UPDATE).is_some() && want != current {
        fs::write(&path, &want).unwrap();
        return;
    }
    assert!(
        want == current,
        "{file} differs from the host specs; run \
         `{UPDATE}=1 cargo test -p openmoat-hosts --test docs`"
    );
}

#[test]
fn install_lists_each_agents_directory_and_hook_entries() {
    check("docs/INSTALL.md", &[("hosts-install", install_table())]);
}

#[test]
fn threat_model_lists_each_agents_gaps_and_hook_failure() {
    check("docs/THREAT_MODEL.md", &[("hosts-gaps", gaps_list())]);
}

#[test]
fn readme_lists_each_agent_and_how_it_is_hooked() {
    check("README.md", &[("hosts-agents", agents_table())]);
}

#[test]
fn architecture_lists_each_agents_tool_mapping() {
    check("docs/ARCHITECTURE.md", &[("hosts-tools", tools_table())]);
}

/// What the README says protects an agent's calls follows from its sandbox:
/// "hook + OS sandbox" exactly when OpenMoat writes one, with where it runs
/// when it is not written on native Windows.
#[test]
fn each_protection_text_matches_the_hosts_sandbox() {
    for host in Host::EVERY {
        let spec: &HostSpec = host.spec();
        let text = spec.docs.protection;
        assert!(!spec.docs.hooked_by.is_empty(), "{host:?}");
        if spec.install.is_none() {
            assert!(text.contains("openmoat run"), "{host:?}: {text}");
            continue;
        }
        match &spec.sandbox {
            None => assert_eq!(text, "hook only", "{host:?}"),
            Some(sandbox) if sandbox.unavailable_on_windows.is_none() => {
                assert_eq!(text, "hook + OS sandbox", "{host:?}");
            }
            Some(_) => assert!(
                text.starts_with("hook + OS sandbox (") && text.contains("); hook only on "),
                "{host:?}: {text}"
            ),
        }
    }
}

/// The quoted strings a `match` arm on `line` matches (`"a" | "b" =>`,
/// `("a" | "b", _) =>`), the empty string aside.
fn arm_literals(line: &str) -> Vec<&str> {
    let line = line.trim_start();
    if !(line.starts_with('"') || line.starts_with("(\"")) {
        return Vec::new();
    }
    let Some((pattern, _)) = line.split_once("=>") else {
        return Vec::new();
    };
    pattern
        .split('"')
        .skip(1)
        .step_by(2)
        .filter(|s| !s.is_empty())
        .collect()
}

/// `dir`'s `.rs` files that map tools, in its subdirectories too (OpenCode's
/// `tools/v1.rs` and `tools/v2.rs`): all but tests, bench and doc rows.
fn mapping_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() && !["fixtures", "integration", "tests"].contains(&name.as_str()) {
            mapping_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && !["tests.rs", "bench.rs", "doc.rs"].contains(&name.as_str())
        {
            out.push(path);
        }
    }
}

/// Every tool name (or tool action) a host's code matches in a `match` arm
/// appears, in backticks, in that host's rows of the tool table, so a tool the
/// adapter learns cannot be left out of the docs. Code shared by several
/// hosts' formats (`wire/pre_tool_use`) is covered by the rows of the hosts
/// that use it together.
#[test]
fn every_tool_an_adapter_matches_has_a_documentation_row() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut rows_of: BTreeMap<PathBuf, String> = BTreeMap::new();
    for host in Host::ALL {
        let spec = host.spec();
        assert!(!spec.docs.tools.is_empty(), "{host:?} documents no tool");
        let mut rows = String::new();
        for row in spec.docs.tools {
            let _ = writeln!(rows, "{} {} {}", row.tool, row.reads, row.action);
        }
        let module = spec.id.replace('-', "_");
        let main = src.join("host").join(format!("{module}.rs"));
        let text = fs::read_to_string(&main).unwrap_or_else(|e| panic!("{main:?}: {e}"));
        let mut files = vec![main];
        mapping_files(&src.join("host").join(&module), &mut files);
        if text.contains("wire::pre_tool_use") {
            files.push(src.join("wire/pre_tool_use.rs"));
            mapping_files(&src.join("wire/pre_tool_use"), &mut files);
        }
        for file in files {
            rows_of.entry(file).or_default().push_str(&rows);
        }
    }
    let (mut missing, mut checked) = (Vec::new(), 0);
    for (file, rows) in &rows_of {
        for line in fs::read_to_string(file).unwrap().lines() {
            for literal in arm_literals(line) {
                checked += 1;
                if !rows.contains(&format!("`{literal}`")) {
                    missing.push(format!("{}: `{literal}`", file.display()));
                }
            }
        }
    }
    assert!(checked > 50, "the scan found too few tools: {checked}");
    assert!(
        missing.is_empty(),
        "tools matched in code but missing from the docs rows (`host/<id>/doc.rs`):\n{}",
        missing.join("\n")
    );
}

#[test]
fn arm_literals_reads_the_patterns_of_an_arm() {
    assert_eq!(arm_literals(r#"  "a" | "b" => x,"#), ["a", "b"]);
    assert_eq!(
        arm_literals(r#"  ("open" | "x", Some(u)) => y"#),
        ["open", "x"]
    );
    assert_eq!(arm_literals(r#"  "" => cd,"#), Vec::<&str>::new());
    assert!(arm_literals(r#"  let a = "b";"#).is_empty());
    assert!(arm_literals(r#"  name if name == "x" => y"#).is_empty());
}

#[test]
fn splice_replaces_only_the_named_block_and_keeps_its_indent() {
    let text = "a\n  <!-- generated:x -->\n  old\n  <!-- /generated -->\nb\n";
    let body = ["one".to_owned(), "two".to_owned()];
    assert_eq!(
        splice(text, "x", &body).unwrap(),
        "a\n  <!-- generated:x -->\n  one\n  two\n  <!-- /generated -->\nb\n"
    );
    assert!(splice(text, "y", &body).is_err());
    assert!(splice("<!-- generated:x -->", "x", &body).is_err());
}

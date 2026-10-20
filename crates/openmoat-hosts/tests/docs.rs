//! The host tables in the docs that a [`HostSpec`] fully states are generated
//! from it, between `<!-- generated:<name> -->` and `<!-- /generated -->`, so a
//! spec change and its documentation cannot drift apart. Tables that need more
//! than the spec says (what each hook sees, the per-case "When the hook fails"
//! table) stay hand-written.
//!
//! Regenerate with `OPENMOAT_TEST_UPDATE_DOCS=1 cargo test -p openmoat-hosts --test docs`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::Host;

/// Every host, the installable ones and those that run another's hook.
const HOSTS: [Host; 5] = [
    Host::ClaudeCode,
    Host::Codex,
    Host::Cursor,
    Host::OpenClaw,
    Host::Continue,
];

const END: &str = "<!-- /generated -->";
const UPDATE: &str = "OPENMOAT_TEST_UPDATE_DOCS";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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
    HOSTS
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

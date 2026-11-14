//! Host names written outside the host modules: each host's id, directories,
//! program names, display name and file names, all from its spec
//! ([`Facts`]), in the shared code of every crate, the shared end-to-end
//! tests, `scripts/` and the default policy. Each place has a list in
//! [`crate::allowed`] that only shrinks.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::allowed::{
    ALLOWED_IN_POLICY, ALLOWED_IN_SCRIPTS, ALLOWED_IN_SHARED_TESTS, ALLOWED_NAMES,
};
use crate::facts::Facts;
use crate::literals::{Literal, literals};
use crate::{
    Found, SOURCE_ROOTS, check_only_shrinks, is_host_or_test_file, module_names, relative_to,
    rust_files,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether each line of `lines` is left out: inside a `// generated:` …
/// `// /generated` block, or a file's inline tests (`#[cfg(test)]` and `mod
/// tests {` at the top level, to its `}`), test data as `tests.rs` is.
fn skipped_lines(lines: &[&str]) -> Vec<bool> {
    let mut generated = false;
    let mut tests = false;
    let mut skip = Vec::with_capacity(lines.len());
    for (at, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("// generated:") {
            generated = true;
        } else if trimmed.starts_with("// /generated") {
            generated = false;
        }
        if line.starts_with("#[cfg(")
            && line
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| word == "test")
            && lines
                .get(at + 1)
                .is_some_and(|next| next.starts_with("mod ") && next.ends_with(" {"))
        {
            tests = true;
        }
        skip.push(generated || tests);
        if tests && *line == "}" {
            tests = false;
        }
    }
    skip
}

/// Whether `literal`, exactly a host's id or program, is a word that only
/// shares the host's name: a JSON key (`"cursor": cursor`), or an item of a
/// list of words that name no host (`wget`'s `"continue",` among its option
/// names, `"cn"` among top-level domains).
fn is_a_word(lines: &[&str], literal: &Literal, facts: &Facts) -> bool {
    let text = literal.text.as_str();
    if !facts.ids.contains(&text) && !facts.programs.contains(&text) {
        return false;
    }
    if literal.key {
        return true;
    }
    let list_line = |i: usize| {
        let line = lines.get(i)?.trim();
        (line.starts_with('"') && line.ends_with("\",")).then(|| literals(line))
    };
    let names_none = |items: &[Literal]| {
        items
            .iter()
            .filter(|item| item.text != text)
            .all(|item| facts.named_in(&format!("\"{}\"", item.text)).is_none())
    };
    match list_line(literal.line) {
        Some(own) if own.len() > 1 => names_none(&own),
        Some(_) => [literal.line.wrapping_sub(1), literal.line + 1]
            .iter()
            .all(|i| list_line(*i).is_some_and(|items| names_none(&items))),
        None => false,
    }
}

/// `text` with each format argument (`{claude}`, `{name:<16}`) emptied: it
/// names a variable, not a host. A brace glob (`{.claude,.codex}`) stays.
fn without_format_arguments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..=open]);
        rest = &rest[open + 1..];
        let close = rest.find('}').unwrap_or(rest.len());
        let name = rest[..close].split(':').next().unwrap_or("");
        if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            rest = &rest[close..];
        }
    }
    out.push_str(rest);
    out
}

/// Each line of Rust `source` with a literal that names a host, outside
/// [`skipped_lines`]: `<line>: <what>`.
fn rust_lines(source: &str, facts: &Facts) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let skipped = skipped_lines(&lines);
    let mut named = BTreeMap::new();
    for literal in literals(source) {
        let at = literal.line;
        if skipped.get(at).copied().unwrap_or(false)
            || named.contains_key(&at)
            || is_a_word(&lines, &literal, facts)
        {
            continue;
        }
        let text = without_format_arguments(&literal.text);
        if let Some(what) = facts.named_in(&format!("\"{text}\"")) {
            named.insert(at, format!("{}: {what}", at + 1));
        }
    }
    named.into_values().collect()
}

/// Each line of a script or YAML file that names a host, outside `#`
/// comment lines and the lines `skip` marks.
fn text_lines(text: &str, skip: &[bool], facts: &Facts) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(at, line)| {
            !skip.get(*at).copied().unwrap_or(false) && !line.trim_start().starts_with('#')
        })
        .filter_map(|(at, line)| {
            facts
                .named_in(line)
                .map(|what| format!("{}: {what}", at + 1))
        })
        .collect()
}

fn record(found: &mut Found, file: String, lines: Vec<String>) {
    if !lines.is_empty() {
        found.insert(file, lines);
    }
}

#[test]
fn the_matcher_finds_hosts_in_code_not_in_words() {
    let facts = Facts::from_specs();
    assert!(facts.ids.contains(&"continue"), "{:?}", facts.ids);
    assert!(facts.programs.contains(&"claude"), "{:?}", facts.programs);
    assert!(facts.display_names.contains(&"Gemini CLI"));
    assert!(facts.files.contains(&"settings.json"), "{:?}", facts.files);
    for named in [
        "\"**/.codex/config.toml\"",
        "\"~/.claude/settings.json\"",
        "\"codex\"",
        "\"guard --host continue\"",
        "\"hosts/continue/x\"",
        "\"claude\"",
        "\"/usr/local/bin/cursor-agent --version\"",
        "\"Claude Code is not installed\"",
        "\"hooks.json\"",
        "\"/tmp/claude-*/**\"",
        "\"**/.claude.json\"",
        "fs.read: [\"~/.codex/auth.json\"]",
        "  - \"{pi,*/pi} auth print-api-key*\"",
    ] {
        assert!(facts.named_in(named).is_some(), "{named}");
    }
    for not_named in [
        "\"--continue\"",
        "\"continue the loop\"",
        "\"claude-in-the-name\"",
        "\"~/.codexrc\"",
        "\"settings.jsonl\"",
        "\"**/.cargo/config.toml\"",
        "\"712-pi-dialog-timeout.md\"",
    ] {
        assert_eq!(facts.named_in(not_named), None, "{not_named}");
    }
    let list = "const F: &[&str] = &[\n    \"quiet\",\n    \"continue\",\n    \"spider\",\n];\n";
    assert_eq!(rust_lines(list, &facts), Vec::<String>::new());
    let hosts = "const H: &[&str] = &[\n    \"codex\",\n    \"continue\",\n];\n";
    assert_eq!(
        rust_lines(hosts, &facts),
        ["2: id `codex`", "3: id `continue`"]
    );
    let domains = "const D: &[&str] = &[\n    \"com\", \"cn\", \"in\",\n];\n";
    assert_eq!(rust_lines(domains, &facts), Vec::<String>::new());
    assert_eq!(
        without_format_arguments("{claude} {name:<16} {.claude,.codex}"),
        "{} {} {.claude,.codex}"
    );
    let key = "json!({ \"cursor\": cursor, \"host\": \"cursor\" })";
    assert_eq!(rust_lines(key, &facts), ["1: id `cursor`"]);
    let code = "// \"codex\" in a comment\nlet a = '\"'; let p = r#\"~/.codex/x\"#;\n\
                #[cfg(all(test, unix))]\nmod tests {\n    const C: &str = \"codex\";\n}\n\
                const D: &str = \"Gemini CLI\";\n";
    assert_eq!(
        rust_lines(code, &facts),
        ["2: directory `.codex`", "7: display name `Gemini CLI`"]
    );
}

/// Every crate's shared code: the sources outside the host modules and test
/// files, `openmoat-hosts`' own shared code (`wire/`, `contract/`, …)
/// included.
#[test]
fn only_host_modules_name_a_host_by_its_spec_facts() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let facts = Facts::from_specs();
    let mut files = Vec::new();
    for root in SOURCE_ROOTS {
        rust_files(&crates.join(root), &mut files);
    }
    let mut found = Found::new();
    for file in files {
        let relative = relative_to(&file, &crates);
        if !is_host_or_test_file(&relative) {
            let lines = rust_lines(&fs::read_to_string(&file).unwrap(), &facts);
            record(&mut found, relative, lines);
        }
    }
    check_only_shrinks(&found, ALLOWED_NAMES, "a host", "ALLOWED_NAMES");
}

/// The core decides for every host and knows none: outside the blocks
/// `tests/protect.rs` writes from the specs and its inline tests, no line of
/// `openmoat-core/src` names a host by a fact of its spec (a directory, a
/// program, a file, an id or a name), and no allowance may let one in.
#[test]
fn the_core_names_no_host() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let facts = Facts::from_specs();
    let mut files = Vec::new();
    rust_files(&crates.join("openmoat-core/src"), &mut files);
    assert!(files.len() > 50, "the scan found too little");
    let mut found = Found::new();
    for file in files {
        let relative = relative_to(&file, &crates);
        if !is_host_or_test_file(&relative) {
            let lines = rust_lines(&fs::read_to_string(&file).unwrap(), &facts);
            record(&mut found, relative, lines);
        }
    }
    assert_eq!(
        found,
        Found::new(),
        "take what differs per host from its spec"
    );
    let allowed: Vec<&str> = ALLOWED_NAMES
        .iter()
        .map(|(file, _)| *file)
        .filter(|file| file.starts_with("openmoat-core/"))
        .collect();
    assert_eq!(allowed, Vec::<&str>::new(), "the core gets no allowance");
    // The skipped blocks are the generated ones, each opened once and closed.
    let taint = fs::read_to_string(repo().join(crate::policy_blocks::TAINT)).unwrap();
    for before in [
        crate::policy_blocks::TAINT_BEFORE,
        crate::policy_blocks::METADATA_BEFORE,
    ] {
        assert_eq!(taint.matches(before).count(), 1, "{before}");
    }
    assert_eq!(taint.matches(crate::policy_blocks::CORE_AFTER).count(), 2);
}

/// Whether `relative` (under `e2e/`) is one host's own test file or folder
/// (`codex.rs`, `cursor_sandbox.rs`, `differential/claude.rs`, named by a
/// host's module as [`module_names`] gives them) or a host's row of the
/// `hosts` suite.
fn is_host_test(relative: &str) -> bool {
    let modules = module_names();
    relative.starts_with("hosts/rows/")
        || relative.split('/').any(|part| {
            let stem = part.strip_suffix(".rs").unwrap_or(part);
            modules
                .iter()
                .any(|module| stem == module || stem.starts_with(&format!("{module}_")))
        })
}

/// The end-to-end tests every host shares (`common.rs`, `protection.rs`,
/// `differential/`): what they need of a host should come from its spec.
#[test]
fn shared_end_to_end_tests_name_a_host_only_where_listed() {
    let e2e = repo().join("crates/openmoat-cli/tests/e2e");
    let facts = Facts::from_specs();
    let mut files = Vec::new();
    rust_files(&e2e, &mut files);
    assert!(is_host_test("codex.rs") && is_host_test("cursor_sandbox.rs"));
    assert!(!is_host_test("common.rs") && is_host_test("hosts/rows/pi.rs"));
    assert!(is_host_test("differential/claude.rs") && !is_host_test("differential/scripts.rs"));
    let mut found = Found::new();
    for file in files {
        let relative = relative_to(&file, &e2e);
        if !is_host_test(&relative) {
            let lines = rust_lines(&fs::read_to_string(&file).unwrap(), &facts);
            record(&mut found, relative, lines);
        }
    }
    assert!(found.contains_key("common.rs"), "the scan found too little");
    check_only_shrinks(
        &found,
        ALLOWED_IN_SHARED_TESTS,
        "a host",
        "ALLOWED_IN_SHARED_TESTS",
    );
}

fn script_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            script_files(&path, out);
        } else if path
            .extension()
            .is_some_and(|e| e == "sh" || e == "py" || e == "json")
        {
            out.push(path);
        }
    }
}

/// `scripts/`: the shell and Python tools and their data, which CI and
/// people run against real agents.
#[test]
fn scripts_name_a_host_only_where_listed() {
    let scripts = repo().join("scripts");
    let facts = Facts::from_specs();
    let mut files = Vec::new();
    script_files(&scripts, &mut files);
    let mut found = Found::new();
    for file in files {
        let lines = text_lines(&fs::read_to_string(&file).unwrap(), &[], &facts);
        record(&mut found, relative_to(&file, &scripts), lines);
    }
    assert!(found.len() > 2, "the scan found too little: {found:?}");
    check_only_shrinks(&found, ALLOWED_IN_SCRIPTS, "a host", "ALLOWED_IN_SCRIPTS");
}

/// The lines of `text` inside the blocks of [`crate::policy_blocks::BLOCKS`].
fn policy_blocks(text: &str) -> Vec<bool> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut skip = vec![false; lines.len()];
    for (before, after) in crate::policy_blocks::BLOCKS {
        let starts: Vec<usize> = (0..lines.len())
            .filter(|i| lines[*i].ends_with(before))
            .collect();
        assert_eq!(starts.len(), 1, "`{before}` must start one block");
        let mut at = starts[0] + 1;
        while lines.get(at).is_some_and(|l| l != after) {
            skip[at] = true;
            at += 1;
        }
        assert!(at < lines.len(), "no `{after}` after `{before}`");
    }
    skip
}

/// The default policy, outside the blocks generated from the specs, by the
/// rule each line is in (`kernel-self`).
#[test]
fn the_default_policy_names_a_host_only_where_listed() {
    let text = fs::read_to_string(repo().join(crate::policy_blocks::POLICY))
        .unwrap()
        .replace("\r\n", "\n");
    let skip = policy_blocks(&text);
    assert!(
        skip.iter().filter(|s| **s).count() > 10,
        "no generated block"
    );
    let facts = Facts::from_specs();
    let mut rule = "(before the rules)";
    let mut rules = Vec::new();
    for line in text.lines() {
        if let Some(id) = line.strip_prefix("  - id: ") {
            rule = id.trim();
        }
        rules.push(rule);
    }
    let mut found = Found::new();
    for named in text_lines(&text, &skip, &facts) {
        let at: usize = named.split(':').next().unwrap().parse().unwrap();
        found
            .entry(rules[at - 1].to_owned())
            .or_default()
            .push(named);
    }
    assert!(
        found.contains_key("kernel-self"),
        "the scan found too little"
    );
    check_only_shrinks(&found, ALLOWED_IN_POLICY, "a host", "ALLOWED_IN_POLICY");
}

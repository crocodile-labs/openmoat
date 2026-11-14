//! Rule ids written outside `openmoat_core::rule_id`, in every crate's code
//! (test files and inline tests left out, as `names.rs` leaves them).
//! OpenMoat's own rule ids are written once, as the registry's constants: no
//! other file repeats one as a literal, defines a rule-id constant of its own,
//! or hands a decision a literal rule id. With the conformance runner's check
//! that every rule a decision carries resolves (`rule_id::resolves`), a new
//! rule id has one place to go. The list of exceptions is empty.

use std::fs;
use std::path::Path;

use openmoat_core::diffscan;
use openmoat_core::rule_id::{BUILTIN_RULES, DEFAULT_NET, DEFAULT_PREFIX, POLICY_RULES};

use crate::literals::literals;
use crate::names::skipped_lines;
use crate::{Found, SOURCE_ROOTS, relative_to, rust_files};

/// The files that write rule ids: the registry, and the table of `policy
/// check-diff`'s content checks it refers to.
const REGISTRIES: &[&str] = &[
    "openmoat-core/src/rule_id.rs",
    "openmoat-core/src/rule_id/",
    "openmoat-core/src/diffscan.rs",
];

/// Every id the registry writes. `rule_id::DEFAULT` (`default`) is left out:
/// the word is also a key and a value of several hosts' settings formats.
fn registered() -> Vec<&'static str> {
    BUILTIN_RULES
        .iter()
        .map(|r| r.id)
        .chain(diffscan::RULES.iter().map(|r| r.id))
        .chain(POLICY_RULES.iter().copied())
        .chain([DEFAULT_NET, DEFAULT_PREFIX])
        .collect()
}

/// A rule-id constant's name: `RULE`, `…_RULE` or `RULE_…`.
fn is_rule_name(name: &str) -> bool {
    name == "RULE" || name.ends_with("_RULE") || name.starts_with("RULE_")
}

/// A decision rule id as OpenMoat writes one: lowercase words joined by `-`.
/// A sandbox report's entries are dotted (`seatbelt.agent-config`), never a
/// decision's.
fn looks_like_rule_id(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The arguments of the call that starts at `open` (just after its `(`),
/// split at its top-level commas.
fn arguments(code: &str, open: usize) -> Vec<&str> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut start = open;
    let mut out = Vec::new();
    let bytes = code.as_bytes();
    let mut at = open;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' if quoted => at += 1,
            b'"' => quoted = !quoted,
            b'(' | b'[' | b'{' if !quoted => depth += 1,
            b')' | b']' | b'}' if !quoted && depth == 0 => {
                out.push(code[start..at].trim());
                return out;
            }
            b')' | b']' | b'}' if !quoted => depth -= 1,
            b',' if !quoted && depth == 0 => {
                out.push(code[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    out
}

/// Each problem of `source`: `<line>: <what>`.
fn problems(source: &str, ids: &[&str]) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let skipped = skipped_lines(&lines);
    let kept = |line: usize| !skipped.get(line).copied().unwrap_or(false);
    let mut out = Vec::new();
    for literal in literals(source).into_iter().filter(|l| kept(l.line)) {
        if ids.contains(&literal.text.as_str()) {
            out.push(format!(
                "{}: `{}` is written again: use its `openmoat_core::rule_id` constant",
                literal.line + 1,
                literal.text
            ));
        }
    }
    // Skipped lines stay as empty ones, so the line numbers hold.
    let code: String = lines
        .iter()
        .enumerate()
        .map(|(at, line)| {
            if kept(at) {
                format!("{line}\n")
            } else {
                "\n".to_owned()
            }
        })
        .collect();
    for (at, line) in code.lines().enumerate() {
        let trimmed = line.trim_start();
        let declared = trimmed
            .split_once("const ")
            .filter(|(before, _)| before.is_empty() || before.ends_with(' '))
            .and_then(|(_, rest)| rest.split_once(": &str = \""))
            .filter(|(name, value)| {
                is_rule_name(name) && looks_like_rule_id(value.trim_end_matches("\";"))
            });
        if let Some((name, _)) = declared {
            out.push(format!(
                "{}: `{name}` defines a rule id outside `openmoat_core::rule_id`",
                at + 1
            ));
        }
        if trimmed.contains("rules.push(\"") {
            out.push(format!(
                "{}: a literal rule id pushed onto a decision",
                at + 1
            ));
        }
    }
    for (open, _) in code.match_indices("Decision::single(") {
        let args = arguments(&code, open + "Decision::single(".len());
        if args.get(1).is_some_and(|rule| rule.starts_with('"')) {
            let line = code[..open].matches('\n').count() + 1;
            out.push(format!("{line}: `Decision::single` with a literal rule id"));
        }
    }
    out
}

#[test]
fn the_scan_finds_every_kind_of_rule_id_written_outside_the_registry() {
    let ids = ["kernel-self", "unparseable"];
    let source = "const KERNEL_SELF_RULE: &str = \"own-rule\";\n\
                  fn f() { let d = Decision::single(Verdict::Deny, \"made-up\", why()); }\n\
                  fn g(d: &mut Decision) { d.rules.push(\"another\".into()); }\n\
                  fn h() -> &'static str { \"unparseable\" }\n\
                  // a comment naming `kernel-self` is documentation\n\
                  const PROFILE: &str = \"codex.own-binary\";\n\
                  fn ok() { Decision::single(Verdict::Deny, UNPARSEABLE, \"a reason\"); }\n\
                  #[cfg(test)]\nmod tests {\n    const RULE: &str = \"kernel-self\";\n}\n";
    let found = problems(source, &ids);
    assert_eq!(found.len(), 4, "{found:#?}");
    for line in ["1:", "2:", "3:", "4:"] {
        assert!(
            found.iter().any(|f| f.starts_with(line)),
            "{line} {found:#?}"
        );
    }
}

#[test]
fn rule_ids_are_written_only_in_the_registry() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let ids = registered();
    assert!(ids.len() > 80, "the registry gave too little: {ids:?}");
    let mut files = Vec::new();
    for root in SOURCE_ROOTS {
        rust_files(&crates.join(root), &mut files);
    }
    let mut found = Found::new();
    for file in files {
        let relative = relative_to(&file, &crates);
        if relative.ends_with("/tests.rs")
            || relative.contains("/tests/")
            || REGISTRIES.iter().any(|r| relative.starts_with(r))
        {
            continue;
        }
        let lines = problems(&fs::read_to_string(&file).unwrap(), &ids);
        if !lines.is_empty() {
            found.insert(relative, lines);
        }
    }
    let report: Vec<String> = found
        .iter()
        .map(|(file, lines)| format!("{file}\n    {}", lines.join("\n    ")))
        .collect();
    assert!(found.is_empty(), "{}", report.join("\n"));
}

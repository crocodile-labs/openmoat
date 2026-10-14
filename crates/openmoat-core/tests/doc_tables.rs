//! The verdict tables in `README.md` and `docs/USAGE.md` say "real verdicts from
//! the default policy". This test decides every command in them with the shipped
//! default policy, so a policy change that moves a verdict also has to update the
//! table that shows it to users.
//!
//! A table is the one with the header `| Command | Verdict | Rule |`. Each row lists
//! commands and rule ids in backticks; the verdict is the first word of its column.
//! Every command must get that verdict, and every rule id its decision names must
//! be listed in the row.

use std::fs;
use std::path::Path;

use openmoat_core::{Action, CompiledPolicy, DEFAULT_POLICY, EvalContext, Policy, Verdict};

const HEADER: &str = "| Command | Verdict | Rule |";

struct Row {
    commands: Vec<String>,
    verdict: Verdict,
    rules: Vec<String>,
}

/// The text inside each pair of backticks, with `\|` read as `|`.
fn code_spans(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(|span| span.replace("\\|", "|"))
        .collect()
}

fn rows(doc: &str) -> Vec<Row> {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(doc),
    )
    .unwrap_or_else(|e| panic!("reading {doc}: {e}"));
    let mut lines = text.lines().skip_while(|line| line.trim() != HEADER);
    assert!(lines.next().is_some(), "{doc}: no `{HEADER}` table");
    lines
        .skip(1)
        .take_while(|line| line.starts_with('|'))
        .map(|line| {
            // `\|` inside a code span is a pipe in the command, not a cell border.
            let cells: Vec<String> = line
                .replace("\\|", "\u{0}")
                .split('|')
                .map(|cell| cell.replace('\u{0}', "\\|"))
                .collect();
            assert_eq!(cells.len(), 5, "{doc}: row `{line}` needs three cells");
            let word = cells[2].trim().split([' ', ':']).next().unwrap_or_default();
            Row {
                commands: code_spans(&cells[1]),
                verdict: word
                    .parse()
                    .unwrap_or_else(|e| panic!("{doc}: row `{line}`: {e}")),
                rules: code_spans(&cells[3]),
            }
        })
        .collect()
}

fn check(doc: &str) {
    let policy = Policy::parse(DEFAULT_POLICY).expect("default policy must lint");
    let ctx = EvalContext {
        home: "/Users/me".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    };
    let compiled = CompiledPolicy::compile(&policy, &ctx).expect("default policy must compile");
    let rows = rows(doc);
    assert!(!rows.is_empty(), "{doc}: the verdict table is empty");
    let mut wrong = Vec::new();
    for row in rows {
        assert!(!row.commands.is_empty(), "{doc}: a row names no command");
        for command in &row.commands {
            let decision = compiled.decide(&Action::Shell {
                command: command.clone(),
            });
            let unlisted = decision.rules.iter().any(|rule| !row.rules.contains(rule));
            if decision.verdict != row.verdict || unlisted {
                wrong.push(format!(
                    "  `{command}`: the table says {} {:?}, the policy decides {} {:?}",
                    row.verdict.as_str(),
                    row.rules,
                    decision.verdict.as_str(),
                    decision.rules
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{doc} shows verdicts the default policy does not give:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn readme_table_matches_the_default_policy() {
    check("README.md");
}

#[test]
fn usage_table_matches_the_default_policy() {
    check("docs/USAGE.md");
}

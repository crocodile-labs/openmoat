//! Any command line an agent can send: the lexer, classifier and engine must
//! decide without panicking, and every decision names the rule behind it.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use openmoat_core::{Action, CompiledPolicy, DEFAULT_POLICY, EvalContext, Policy};

/// The default policy, compiled once: compilation dominates a single decision.
fn compiled() -> &'static CompiledPolicy<'static> {
    static POLICY: OnceLock<Policy> = OnceLock::new();
    static COMPILED: OnceLock<CompiledPolicy<'static>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let policy = POLICY.get_or_init(|| Policy::parse(DEFAULT_POLICY).expect("default policy"));
        let ctx = EvalContext {
            home: "/home/me".into(),
            project: Some("/home/me/p".into()),
            cwd: "/home/me/p".into(),
            case_insensitive_paths: false,
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
        };
        CompiledPolicy::compile(policy, &ctx).expect("default policy compiles")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(command) = std::str::from_utf8(data) else {
        return;
    };
    let decision = compiled().decide(&Action::Shell {
        command: command.to_owned(),
    });
    assert!(
        !decision.rules.is_empty(),
        "a decision without a rule: {decision:?}"
    );
    // For a decided line, one more harmless command never makes it less
    // strict: padding a line until a classifier limit stops it must not lower
    // its verdict (strictness: deny > review > defer > allow). A line that
    // was not decided (`unparseable`, an empty line) may become one.
    if decision.rules.iter().any(|rule| rule == "unparseable") {
        return;
    }
    // A line ending in an unescaped `\` continues into what follows, so
    // ` ; true` after it is an argument (`ls \ ; true` lists the file ` `),
    // not one more command.
    let trailing = command.bytes().rev().take_while(|b| *b == b'\\').count();
    if trailing % 2 == 1 {
        return;
    }
    let padded = compiled().decide(&Action::Shell {
        command: format!("{command} ; true"),
    });
    assert!(
        padded.verdict >= decision.verdict,
        "appending `; true` lowered {:?} to {:?}",
        decision.verdict,
        padded.verdict
    );
});

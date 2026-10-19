//! `moat allow --always` turns a command into a literal pattern. For any
//! command it accepts, the pattern must be a valid rule, and a policy that
//! allows only that pattern must allow the command itself.

#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use openmoat_core::{
    Action, CompiledPolicy, Defaults, EvalContext, Policy, RuleGroup, Verdict,
    literal_shell_pattern,
};

fuzz_target!(|data: &[u8]| {
    let Ok(command) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(pattern) = literal_shell_pattern(command) else {
        return;
    };
    // Built as values, the way the overlay is (the YAML writer escapes what
    // YAML cannot hold raw), so only the pattern itself is under test.
    let policy = Policy {
        version: 1,
        defaults: Defaults::All(Verdict::Deny),
        scope: None,
        deny: Vec::new(),
        allow: vec![RuleGroup {
            id: "approved".into(),
            // Weaker matches are kept as reason text, so the reason marks them.
            reason: Some("approved".into()),
            shell: vec![pattern.clone()],
            ..RuleGroup::default()
        }],
        ask: Vec::new(),
        defer: Vec::new(),
        approval: None,
        executables: BTreeMap::new(),
        sandbox: None,
        secrets: Vec::new(),
        repo_ask: Vec::new(),
        taint: None,
        require_signed_repo_policy: false,
        mcp: None,
    };
    if let Err(e) = policy.lint() {
        panic!("pattern {pattern:?} for {command:?} does not lint: {e}");
    }
    let ctx = EvalContext {
        home: "/home/me".into(),
        project: Some("/home/me/p".into()),
        cwd: "/home/me/p".into(),
        case_insensitive_paths: false,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
    };
    let compiled = CompiledPolicy::compile(&policy, &ctx).expect("linted policy compiles");
    let decision = compiled.decide(&Action::Shell {
        command: command.to_owned(),
    });
    // For a command of plain words, the full-argv shell atom is exactly the
    // approved pattern, so the rule must take part in the decision (as the
    // verdict or as context when another atom is stricter). Other shapes
    // (assignments, operators, substitutions) produce atoms the literal
    // pattern does not describe and are only checked for panics above.
    let plain = command
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || " -_./:,+@%*?[]{}!".contains(c))
        // the command after leading reserved words (`do x`) is the one classified;
        // an assignment or a `for` header sets a variable and runs no command
        && command
            .split_whitespace()
            .find(|w| !["do", "then", "else", "elif", "if", "while", "until", "!", "{"].contains(w))
            .is_some_and(|w| !w.contains('=') && w != "for");
    // A command the classifier cannot parse asks before any rule is consulted
    // (unparseable ⇒ ask), so its approval cannot take part (`sh -ee.a`).
    let unparseable = decision.rules.iter().any(|r| r == "unparseable");
    if plain && !unparseable {
        let mentioned = decision
            .reasons
            .iter()
            .chain(&decision.context)
            .any(|r| r.starts_with("approved: shell"));
        assert!(
            mentioned,
            "pattern {pattern:?} did not match {command:?}: {decision:?}"
        );
    }
});

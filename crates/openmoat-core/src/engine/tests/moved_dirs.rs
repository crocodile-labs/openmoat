//! `moved_dirs` validation (#399): the engine fails closed on an entry whose
//! `default` could alias every pattern body in [`EvalContext::spellings`]
//! (empty, whitespace or a bare `/`) or does not look like a directory, so a
//! caller's mistake cannot silently widen every rule.

use super::*;

/// A `moved_dirs` entry with an empty, whitespace or bare `/` default would
/// alias every pattern body in [`EvalContext::spellings`] and silently widen
/// every rule, so [`CompiledPolicy::compile`] rejects it (#399). The engine
/// fails closed; the CLI is not the only line of defence.
#[test]
fn compile_rejects_moved_dirs_defaults_that_alias_every_pattern() {
    let p = policy("version: 1\ndefaults: review\n");
    for bad in ["", "  ", "/", "relative/path"] {
        let bad_ctx = EvalContext {
            moved_dirs: vec![(bad.to_owned(), "/x".to_owned())],
            ..ctx()
        };
        let err = CompiledPolicy::compile(&p, &bad_ctx)
            .expect_err(&format!("empty-ish `{bad}` must fail compile"));
        assert!(
            matches!(&err, PolicyError::Rule { rule, .. } if rule == "context.moved_dirs"),
            "wrong error: {err:?}"
        );
    }
    // The CLI legitimately lists the same `default` twice when the moved
    // directory has both an as-written and a resolved spelling (or appears in
    // both the environment and the recorded host dir), so a repeat is kept.
    let repeat = EvalContext {
        moved_dirs: vec![
            ("~/.claude".into(), "/srv/claude".into()),
            ("~/.claude".into(), "/vol/srv/claude".into()),
        ],
        ..ctx()
    };
    assert!(CompiledPolicy::compile(&p, &repeat).is_ok());
    let ok = EvalContext {
        moved_dirs: vec![("~/.claude".into(), "/srv/claude".into())],
        ..ctx()
    };
    assert!(CompiledPolicy::compile(&p, &ok).is_ok());
}

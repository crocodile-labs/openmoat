# openmoat-core

The decision core of [OpenMoat](https://github.com/crocodile-labs/openmoat): policy
model, POSIX shell lexer and classifier, pattern matching, path normalisation, the
decision engine and the policy compiler for OS layers.

**Pure by construction.** No I/O, no OS calls, no `unsafe`, no internal
dependencies. The crate builds for `wasm32-unknown-unknown`, and an
architecture test pins the dependency allowlist and a 500-line file budget.

```rust
use openmoat_core::{Action, CompiledPolicy, DEFAULT_POLICY, EvalContext, Policy, Verdict};

let policy = Policy::parse(DEFAULT_POLICY)?;
let ctx = EvalContext {
    home: "/Users/me".into(),
    project: Some("/p".into()),
    real_home: None,
    real_project: None,
    moved_dirs: Vec::new(),
    cwd: "/p".into(),
    case_insensitive_paths: false,
};
let compiled = CompiledPolicy::compile(&policy, &ctx)?;
let decision = compiled.decide(&Action::Shell { command: "cat ~/.ssh/id_rsa".into() });
assert_eq!(decision.verdict, Verdict::Deny);
```

Policy semantics are specified in
[docs/POLICY.md](https://github.com/crocodile-labs/openmoat/blob/main/docs/POLICY.md)
and [docs/ARCHITECTURE.md](https://github.com/crocodile-labs/openmoat/blob/main/docs/ARCHITECTURE.md)
§3–4, and checked by the conformance fixtures in the repository's `tests/conformance/`.

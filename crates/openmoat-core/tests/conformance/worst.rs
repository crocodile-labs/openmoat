//! The worst session taint there is, which every fixture is also decided
//! under: taint only tightens, so it must never loosen a verdict.

use openmoat_core::{Taint, TaintLabel, TaintSecret};

/// A session that read a secret, private data and untrusted content, with a
/// label of every kind (ADR-126; `label_set` adds the implied ones).
pub fn worst_taint() -> Taint {
    Taint {
        secrets: vec![TaintSecret {
            source: "read /Users/me/.ssh/id_rsa".into(),
            host: None,
        }],
        untrusted: Some("fetch evil.example".into()),
        private: Some("read /Users/me/.codex/auth.json".into()),
        seen: Some("the output of `gh issue view 1`".into()),
        labels: ["web", "mcp:evil", "unknown-tool"]
            .into_iter()
            .map(|name| TaintLabel {
                name: name.into(),
                source: format!("a {name} read"),
            })
            .collect(),
    }
}

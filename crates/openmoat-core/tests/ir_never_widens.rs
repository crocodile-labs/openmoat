//! Property test: lowering never widens (ADR-019).
//!
//! Random policies over a small vocabulary of paths, hosts, exclusions, root
//! placeholders and defaults are lowered and checked against the engine on
//! random reads, writes, connections and fetches. Whenever the IR allows an
//! atom, the engine must allow it too. The generator is a fixed-seed xorshift,
//! so a failure reproduces exactly; proptest is not a dependency of the core.

use std::fmt::Write as _;

use openmoat_core::ir::{Effect, lower};
use openmoat_core::{AtomicAction, CompiledPolicy, EvalContext, Policy, Verdict};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap_or(0)
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const PATH_PATTERNS: &[&str] = &[
    "${project}/**",
    "${project}",
    "!${project}/.git/**",
    "${project}/src/*.rs",
    "~/.ssh/**",
    "!~/.ssh/known_hosts",
    "~/**",
    "**/.env",
    "**/.env.*",
    "!**/.env.example",
    "/etc/**",
    "!/etc/hosts",
    "/tmp/*",
    "/**",
];

const HOST_PATTERNS: &[&str] = &[
    "*.github.com",
    "github.com",
    "!gist.github.com",
    "localhost",
    "169.254.*",
    "*.org",
    "!evil.org",
    "*",
];

const PATHS: &[&str] = &[
    "/p",
    "/p/src/main.rs",
    "/p/.git/config",
    "/p/.env",
    "/p/.env.example",
    "/private/p/src/main.rs",
    "/private/p/.git/HEAD",
    "/Users/me/.ssh/id_rsa",
    "/Users/me/.ssh/known_hosts",
    "/Users/me/.SSH/id_rsa",
    "/Volumes/home/me/.ssh/id_rsa",
    "/Users/me/notes.txt",
    "/etc/hosts",
    "/etc/passwd",
    "/tmp/x",
    "/tmp/a/b",
];

const HOSTS: &[&str] = &[
    "api.github.com",
    "github.com",
    "gist.github.com",
    "localhost",
    "169.254.169.254",
    "metadata.google.internal",
    "rust-lang.org",
    "evil.org",
    "example.com",
];

const VERDICTS: &[&str] = &["allow", "review", "deny"];

fn list(rng: &mut Rng, key: &str, vocabulary: &[&str]) -> String {
    if rng.below(2) == 0 {
        return String::new();
    }
    let patterns: Vec<String> = (0..=rng.below(3))
        .map(|_| format!("'{}'", rng.pick(vocabulary)))
        .collect();
    format!("    {key}: [{}]\n", patterns.join(", "))
}

fn policy(rng: &mut Rng) -> Policy {
    let mut yaml = format!(
        "version: 1\ndefaults: {{ '*': {}, net: {}, fetch: {}, fs.write: {} }}\n",
        rng.pick(VERDICTS),
        rng.pick(VERDICTS),
        rng.pick(VERDICTS),
        rng.pick(VERDICTS),
    );
    let mut id = 0;
    for section in ["deny", "allow", "review"] {
        let mut groups = String::new();
        for _ in 0..rng.below(4) {
            id += 1;
            // The `mcp` pattern keeps a group valid when every list came out empty.
            let _ = writeln!(groups, "  - id: r{id}\n    mcp: ['unused']");
            groups.push_str(&list(rng, "fs.read", PATH_PATTERNS));
            groups.push_str(&list(rng, "fs.write", PATH_PATTERNS));
            groups.push_str(&list(rng, "net", HOST_PATTERNS));
            groups.push_str(&list(rng, "fetch", HOST_PATTERNS));
        }
        if groups.is_empty() {
            let _ = writeln!(yaml, "{section}: []");
        } else {
            let _ = write!(yaml, "{section}:\n{groups}");
        }
    }
    Policy::parse(&yaml).expect("generated policy must lint")
}

fn context(rng: &mut Rng) -> EvalContext {
    EvalContext {
        home: "/Users/me".into(),
        project: (rng.below(4) != 0).then(|| "/p".into()),
        real_home: (rng.below(3) == 0).then(|| "/Volumes/home/me".into()),
        real_project: (rng.below(3) == 0).then(|| "/private/p".into()),
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: rng.below(2) == 0,
    }
}

fn atom(rng: &mut Rng) -> AtomicAction {
    let path = rng.pick(PATHS).to_owned();
    let host = rng.pick(HOSTS).to_owned();
    match rng.below(4) {
        0 => AtomicAction::FsRead { path },
        1 => AtomicAction::FsWrite { path },
        2 => AtomicAction::Net { host },
        _ => AtomicAction::Fetch { host },
    }
}

#[test]
fn lowering_never_allows_what_the_engine_does_not() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut allowed = 0;
    for _ in 0..600 {
        let policy = policy(&mut rng);
        let ctx = context(&mut rng);
        let engine = CompiledPolicy::compile(&policy, &ctx).unwrap();
        let checker = lower(&policy, &ctx).unwrap().checker().unwrap();
        for _ in 0..40 {
            let atom = atom(&mut rng);
            let hook = engine.evaluate_atomic(&atom).map(|d| d.verdict);
            if checker.check(&atom) == Some(Effect::Allow) {
                allowed += 1;
                assert_eq!(
                    hook,
                    Some(Verdict::Allow),
                    "the IR widens {atom:?} in {ctx:?} for\n{policy:#?}"
                );
            }
        }
    }
    assert!(
        allowed > 1000,
        "the generator produced only {allowed} IR allows"
    );
}

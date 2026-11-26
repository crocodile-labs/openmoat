use super::Tail;
use crate::kind::Kind;
use crate::pattern::GlobPattern;
use crate::pattern::word::WordGlob;
use crate::{DEFAULT_POLICY, EvalContext, Policy};

fn ends(texts: &[&str]) -> Tail {
    Tail::EndsWith(texts.iter().map(|t| (*t).to_owned()).collect())
}

#[test]
fn the_tail_is_the_literal_end_of_the_glob() {
    for (glob, tail) in [
        ("**/.env", ends(&[".env"])),
        ("*.pem", ends(&[".pem"])),
        ("/a/b", ends(&["a/b"])),
        ("{gh,*/gh}", ends(&["gh", "gh"])),
        (
            "{docker,*/podman}",
            Tail::EndsWith(vec!["docker".into(), "podman".into()]),
        ),
        ("**/{a,**/b}", ends(&["a", "b"])),
        ("**/*.{pem,key}", ends(&["pem", "key"])),
        ("x{a,b}.json", ends(&[".json"])),
        (
            "**/.git/hooks/**",
            Tail::Contains(vec![".git/hooks".into()]),
        ),
        ("**/sécret/key", ends(&["cret/key"])),
        ("[ab]c", ends(&["c"])),
        ("a\\*b", ends(&["b"])),
    ] {
        assert_eq!(Tail::of(glob), tail, "{glob}");
    }
    // nothing literal at the end, or an end this does not read
    for glob in [
        "**",
        "*",
        "a*",
        "a?",
        "[ab]",
        "{a,*}",
        "{a,b*}",
        "**/é",
        "{a,{b,c}}",
        "[}]",
        "a\\}",
        "{a,[b]}",
        "/**",
        "a/**/**",
        "/",
    ] {
        assert_eq!(Tail::of(glob), Tail::Any, "{glob}");
    }
}

#[test]
fn only_an_ascii_candidate_without_a_backslash_is_refused() {
    let tail = Tail::of("**/.env");
    assert!(!tail.may_match("/p/.envx", false));
    assert!(!tail.may_match("/p/.ENV", false));
    assert!(tail.may_match("/p/.ENV", true));
    assert!(
        tail.may_match("/p/é/x", false),
        "non-ASCII goes to the regex"
    );
    assert!(
        tail.may_match("C:\\p\\x", false),
        "a `\\` goes to the regex"
    );
    let dir = Tail::of("**/.git/hooks/**");
    assert!(dir.may_match("/p/.git/hooks/pre-commit", false));
    assert!(!dir.may_match("/p/.git/config", false));
}

fn ctx(case_insensitive_paths: bool) -> EvalContext {
    EvalContext {
        home: "/Users/me".into(),
        project: Some("/Users/me/code/app".into()),
        real_home: Some("/Volumes/h/me".into()),
        real_project: None,
        moved_dirs: vec![("~/.codex".into(), "/srv/codex".into())],
        cwd: "/Users/me/code/app".into(),
        case_insensitive_paths,
    }
}

/// Candidates every pattern is also tried against: paths a session touches,
/// in other cases, with non-ASCII letters and Windows separators.
const PATHS: [&str; 14] = [
    "/Users/me/code/app/src/lib.rs",
    "/Users/me/code/app/.env",
    "/Users/me/code/app/.git/hooks/pre-commit",
    "/Users/me/CODE/App/.ENV.local",
    "/Users/me/.ssh/id_ed25519",
    "/Users/me/.SSH/ID_RSA",
    "/Users/me/.\u{212A}ube/config",
    "/Users/me/code/app/sécret.pem",
    "C:\\Users\\me\\.ssh\\id_rsa",
    "/tmp/x",
    "/",
    "",
    "api.github.com",
    "AWS_SECRET_ACCESS_KEY",
];

fn flipped(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Every glob of the default policy, spelled for a context, answers every
/// candidate as its regex does: its own matches and near misses
/// (`widen::samples`), those with their case flipped, and [`PATHS`].
#[test]
fn every_default_glob_answers_as_its_regex() {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let groups = policy
        .deny
        .iter()
        .chain(&policy.allow)
        .chain(&policy.review)
        .chain(&policy.defer);
    let mut checked = 0;
    for group in groups {
        for kind in Kind::ALL.into_iter().filter(|k| *k != Kind::Shell) {
            for raw in group.patterns(kind) {
                for case_insensitive in [false, true] {
                    for spelled in ctx(case_insensitive).spellings(raw) {
                        let glob = GlobPattern::compile(&spelled, case_insensitive).unwrap();
                        let mut candidates = crate::widen::samples::glob(&spelled);
                        candidates.extend(candidates.clone().iter().map(|c| flipped(c)));
                        candidates.extend(PATHS.iter().map(|p| (*p).to_owned()));
                        for candidate in &candidates {
                            let by_regex = glob.matcher.regex_match(candidate)
                                || glob.dir.as_ref().is_some_and(|d| d.regex_match(candidate));
                            assert_eq!(glob.is_match(candidate), by_regex, "{spelled} {candidate}");
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(checked > 10_000, "{checked}");
}

/// The same for every word glob of the default policy's shell patterns.
#[test]
fn every_default_shell_word_answers_as_its_regex() {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let groups = policy
        .deny
        .iter()
        .chain(&policy.allow)
        .chain(&policy.review)
        .chain(&policy.defer);
    let programs = [
        "git",
        "gh",
        "/usr/bin/gh",
        "GH",
        "docker",
        "sh",
        "bash",
        "x\\y",
        "é",
    ];
    let mut checked = 0;
    for pattern in groups.flat_map(|g| &g.shell) {
        let body = pattern.strip_prefix('!').unwrap_or(pattern);
        let words = crate::lexer::lex(body)
            .unwrap()
            .into_iter()
            .filter_map(|t| match t {
                crate::lexer::Token::Word(w) => Some(w.text),
                _ => None,
            });
        for word in words {
            let Ok(WordGlob::Glob(glob)) = WordGlob::new(&word) else {
                continue;
            };
            let mut candidates = crate::widen::samples::glob(&word);
            candidates.extend(candidates.clone().iter().map(|c| flipped(c)));
            candidates.extend(programs.iter().map(|p| (*p).to_owned()));
            for candidate in &candidates {
                assert_eq!(
                    glob.is_match(candidate),
                    glob.regex_match(candidate),
                    "{word} {candidate}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 1_000, "{checked}");
}

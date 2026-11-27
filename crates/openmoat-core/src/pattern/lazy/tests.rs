use std::sync::Arc;

use super::{Defer, LazyGlob, Options, Unbuilt};
use crate::kind::Kind;
use crate::pattern::word::{WordGlob, cannot_fail};
use crate::pattern::{Built, GlobPattern};
use crate::{DEFAULT_POLICY, EvalContext, Policy};

fn options(case_insensitive: bool, backslash_escape: Option<bool>) -> Options {
    Options {
        literal_separator: true,
        case_insensitive,
        backslash_escape,
    }
}

fn glob(pattern: &str, case_insensitive: bool) -> LazyGlob {
    LazyGlob::build(pattern, options(case_insensitive, None), &Defer::Never).unwrap()
}

const PATTERNS: [&str; 29] = [
    "/Users/me/.ssh/**",
    "/Users/me/.ssh",
    "/Users/me/.hermes/{auth.json,mcp-tokens,mcp-tokens/**,profiles/*/auth.json}",
    "/Users/me/.local/share/opencode/{auth.json,opencode*.db*}",
    "/Users/me/.kube/**",
    "/Users/me/.aws/credentials",
    "**/.env",
    "**/.env.*",
    "*.pem",
    "/Users/me/projects/[a-c]*/x",
    "/Users/me/esc\\*aped",
    "C:/Users/me/.ssh/**",
    "/",
    "",
    // ends and holds the tail check reads
    "**/.git/hooks/**",
    "**/.git/hooks",
    "**/{.envrc,.env.*}",
    "**/{a,**/b}",
    "{gh,*/gh}",
    "**/*.{pem,key}",
    "**/sécret/key",
    "**/sécret",
    "**/[}]x",
    "**/a\\}",
    "**/a/**/b/**",
    // a spliced directory's literal glob characters (`paths::glob_literal`)
    "/Users/a[*]b/.ssh/**",
    "/Users/a[[]x[]]b/.ssh",
    "/k/p[{]q[,]r[}]/{a,b}",
    "**/s[?]",
];

const CANDIDATES: [&str; 54] = [
    "/Users/me/.ssh/id_rsa",
    "/users/ME/.SSH/id_rsa",
    "/Users/me/.ssh",
    "/Users/me/.ss",
    "/Users/me",
    "",
    "/",
    "/Users/me/.hermes/auth.json",
    "/Users/me/.hermes/profiles/work/auth.json",
    "/Users/me/.hermes/mcp-tokens",
    "/Users/me/.local/share/opencode/opencode.db-wal",
    // KELVIN SIGN and LONG S fold to ASCII letters under Unicode case folding.
    "/Users/me/.\u{212A}ube/config",
    "/U\u{17F}ers/me/.ssh/id_rsa",
    "/Users/mé/.ssh/id_rsa",
    "C:\\Users\\me\\.ssh\\id_rsa",
    "C:/Users/me/.ssh/id_rsa",
    "/p/.env",
    "/p/.env.local",
    "key.pem",
    "/Users/me/projects/b1/x",
    "/Users/me/esc*aped",
    "/p/.git/hooks",
    "/p/.GIT/Hooks/pre-commit",
    "/p/.git/hooksx/y",
    ".git/hooks",
    "/p/.envrc",
    "/p/.env.x",
    "b",
    "/x/b",
    "/x/a",
    "a",
    "gh",
    "/usr/bin/gh",
    "ghx",
    "/k/x.PEM",
    "/k/x.key",
    "/k/sécret/key",
    "/k/s\u{e9}cret",
    "/k/sEcret",
    "/k/}x",
    "/k/a}",
    "/k/a/w/b/c",
    "/k/a/b",
    "C:\\p\\.git\\hooks\\x",
    "/Users/me/.\u{212A}ube",
    "/Users/a*b/.ssh/id_rsa",
    "/Users/a*b/.ssh",
    "/Users/aXb/.ssh/id_rsa",
    "/Users/a[x]b/.ssh",
    "/Users/axb/.ssh",
    "/k/p{q,r}/a",
    "/k/pqr/b",
    "/k/s?",
    "/k/sx",
];

/// The prefix and tail checks never change a verdict: for every pattern
/// and candidate, in both case modes, the answer is the regex's own. A
/// glob built on first use has the regex and answers of one built at once.
/// A `\` escapes on Unix and separates on Windows (globset's default per
/// platform), so each reading is checked on every platform; a pattern only
/// one reading parses (`**/a\}`) is checked in that one.
#[test]
fn the_prefix_check_agrees_with_the_regex_built_now_or_later() {
    for pattern in PATTERNS {
        let mut built = false;
        for backslash_escape in [true, false] {
            for case_insensitive in [false, true] {
                let options = options(case_insensitive, Some(backslash_escape));
                let Ok(now) = LazyGlob::build(pattern, options, &Defer::Never) else {
                    continue;
                };
                built = true;
                let mark = Arc::new(Unbuilt::default());
                let later =
                    LazyGlob::build(pattern, options, &Defer::Every(Arc::clone(&mark))).unwrap();
                assert!(now.is_built() && !later.is_built(), "{pattern:?}");
                for candidate in CANDIDATES {
                    let why = format!(
                        "{pattern:?} {candidate:?} case_insensitive={case_insensitive} \
                         backslash_escape={backslash_escape}"
                    );
                    assert_eq!(now.is_match(candidate), now.regex_match(candidate), "{why}");
                    assert_eq!(later.is_match(candidate), now.is_match(candidate), "{why}");
                    assert_eq!(
                        later.regex_match(candidate),
                        now.regex_match(candidate),
                        "{why}"
                    );
                }
                assert_eq!(later.regex(), now.regex(), "{pattern:?}");
                assert_eq!(mark.reason(), None);
            }
        }
        assert!(built, "{pattern:?} parses under neither reading of `\\`");
    }
}

#[test]
fn the_prefix_stops_at_the_first_glob_character() {
    assert_eq!(glob("/a/b/{c,d}", false).prefix, "/a/b/");
    assert_eq!(glob("/a/*.pem", false).prefix, "/a/");
    assert_eq!(glob("**/.env", false).prefix, "");
    assert_eq!(glob("/a/é/b", false).prefix, "/a/");
}

/// A glob built on first use that does not build answers "no match", reads
/// as an empty regex, and sets its compile's mark once, with the error a
/// compile would have given; one built at once fails as before.
#[test]
fn a_build_that_fails_later_answers_no_match_and_sets_the_mark() {
    let mark = Arc::new(Unbuilt::default());
    let options = options(false, None);
    assert!(LazyGlob::build("/h{x/**", options, &Defer::Never).is_err());
    assert!(LazyGlob::build("/h{x/**", options, &Defer::Safe(Arc::clone(&mark))).is_err());
    let later = LazyGlob::build("/h{x/**", options, &Defer::Every(Arc::clone(&mark))).unwrap();
    let other = LazyGlob::build("/h[x", options, &Defer::Every(Arc::clone(&mark))).unwrap();
    assert_eq!(mark.reason(), None, "nothing is built before it is asked");
    assert!(!later.is_match("/h{x/a"));
    assert!(!later.is_match("/hx/a"));
    assert_eq!(later.regex(), "");
    let error = crate::policy::PolicyError::BadGlob {
        pattern: "/h{x/**".into(),
        error: globset::Glob::new("/h{x/**").unwrap_err(),
    };
    assert_eq!(mark.reason(), Some(error.to_string().as_str()));
    assert!(!other.is_match("/h[x"));
    assert_eq!(
        mark.reason(),
        Some(error.to_string().as_str()),
        "the first stays"
    );
}

/// Homes and projects holding each glob character: a spelled text with
/// `[`, `{`, `}` or `\` is built at compile, failing as it did, and every
/// other waits for its first use, wherever the character came from.
#[test]
fn only_a_spelled_text_that_cannot_fail_waits() {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let mut waited = 0;
    let mut built_now = 0;
    for c in [
        '[', ']', '{', '}', '\\', '*', '?', ',', '!', '-', 'é', '~', '$',
    ] {
        let home = format!("/h{c}x");
        let ctx = EvalContext {
            home: home.clone(),
            project: Some(format!("{home}/p{c}")),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: format!("{home}/p{c}"),
            case_insensitive_paths: true,
        };
        let mark = Arc::new(Unbuilt::default());
        let mut built = Built::deferring(&mark);
        for group in policy
            .deny
            .iter()
            .chain(&policy.allow)
            .chain(&policy.review)
        {
            for kind in [Kind::FsRead, Kind::FsWrite] {
                for spelled in group.patterns(kind).iter().flat_map(|p| ctx.spellings(p)) {
                    let alone = GlobPattern::compile(&spelled, true);
                    let Ok(glob) = GlobPattern::compile_in(&spelled, true, &mut built) else {
                        let error = GlobPattern::compile_in(&spelled, true, &mut built);
                        assert_eq!(
                            error.unwrap_err().to_string(),
                            alone.unwrap_err().to_string()
                        );
                        continue;
                    };
                    assert!(alone.is_ok(), "{spelled}");
                    let body = spelled.strip_prefix('!').unwrap_or(&spelled);
                    let dir = body.strip_suffix("/**").filter(|d| !d.is_empty());
                    for (text, lazy) in std::iter::once((body, &glob.matcher))
                        .chain(dir.into_iter().zip(glob.dir.as_ref()))
                    {
                        if cannot_fail(text) {
                            waited += 1;
                            // nothing here asks a glob, so none is built yet
                            assert!(!lazy.is_built(), "{text}");
                        } else {
                            built_now += 1;
                            assert!(lazy.is_built(), "{text}");
                        }
                    }
                }
            }
        }
        assert_eq!(mark.reason(), None);
    }
    assert!(waited > 1_000 && built_now > 100, "{waited} {built_now}");
}

/// Candidates every glob is also tried against: paths in other cases, with
/// non-ASCII letters and foldings, and with Windows separators.
const PATHS: [&str; 12] = [
    "/Users/me/proj/src/lib.rs",
    "/Users/me/proj/.env",
    "/Users/me/proj/.git/hooks/pre-commit",
    "/Users/me/PROJ/.ENV.local",
    "/Users/me/.ssh/id_ed25519",
    "/Users/me/.\u{212A}ube/config",
    "/U\u{17F}ers/me/.ssh/id_rsa",
    "/Users/me/proj/sécret.pem",
    "C:\\Users\\me\\.ssh\\id_rsa",
    "/Users/me/proj\\.env",
    "/",
    "",
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

/// Every glob of the default policy, spelled for every sample context, and
/// every shell word: built on first use, it has the regex of the glob built
/// at once, byte for byte, and the same answer on its own matches and near
/// misses (`widen::samples`), their case-flipped forms and [`PATHS`]; and no
/// build fails.
#[test]
fn a_glob_built_on_first_use_is_the_glob_built_at_once() {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let groups: Vec<_> = policy
        .deny
        .iter()
        .chain(&policy.allow)
        .chain(&policy.review)
        .chain(&policy.defer)
        .collect();
    let mut checked = 0;
    for ctx in crate::engine::sample_contexts() {
        let mark = Arc::new(Unbuilt::default());
        let mut later = Built::deferring(&mark);
        let mut now = Built::default();
        let ci = ctx.case_insensitive_paths;
        // The answers are compared in the shortest and the longest homes
        // without moved directories, the regex texts in every context: an
        // answer comes from its regex, and the compare costs a regex each.
        let answers = ctx.moved_dirs.is_empty() && (ctx.home.len() < 10 || ctx.real_home.is_some());
        for group in &groups {
            for kind in [Kind::FsRead, Kind::FsWrite] {
                for spelled in group.patterns(kind).iter().flat_map(|p| ctx.spellings(p)) {
                    let deferred = GlobPattern::compile_in(&spelled, ci, &mut later).unwrap();
                    let eager = GlobPattern::compile_in(&spelled, ci, &mut now).unwrap();
                    assert!(deferred.regexes().eq(eager.regexes()), "{spelled}");
                    if !answers {
                        continue;
                    }
                    let mut candidates = crate::widen::samples::glob(&spelled);
                    candidates.extend(candidates.clone().iter().map(|c| flipped(c)));
                    candidates.extend(PATHS.iter().map(|p| (*p).to_owned()));
                    for candidate in &candidates {
                        let answer = eager.is_match(candidate);
                        assert_eq!(
                            deferred.is_match(candidate),
                            answer,
                            "{spelled} {candidate}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(mark.reason(), None);
    }
    for word in policy
        .deny
        .iter()
        .chain(&policy.allow)
        .flat_map(|g| shell_words(&g.shell))
    {
        let mark = Arc::new(Unbuilt::default());
        let deferred = WordGlob::new_in(&word, &mut Built::deferring(&mark)).unwrap();
        let eager = WordGlob::new(&word).unwrap();
        let mut candidates = crate::widen::samples::glob(&word);
        candidates.extend(candidates.clone().iter().map(|c| flipped(c)));
        candidates.extend(["gh", "/usr/bin/gh", "x\\y", "é", "\u{212A}"].map(str::to_owned));
        for candidate in &candidates {
            assert_eq!(
                deferred.is_match(candidate),
                eager.is_match(candidate),
                "{word}"
            );
            checked += 1;
        }
        if let (WordGlob::Glob(d), WordGlob::Glob(e)) = (&deferred, &eager) {
            assert_eq!(d.regex(), e.regex(), "{word}");
        }
        assert_eq!(mark.reason(), None);
    }
    assert!(checked > 50_000, "{checked}");
}

fn shell_words(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .flat_map(|p| {
            crate::lexer::lex(p.strip_prefix('!').unwrap_or(p))
                .unwrap()
                .into_iter()
                .filter_map(|t| match t {
                    crate::lexer::Token::Word(w) => Some(w.text),
                    _ => None,
                })
        })
        .collect()
}

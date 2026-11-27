use crate::engine::EvalContext;
use crate::kind::Kind;
use crate::paths;
use crate::policy::Policy;

/// [`EvalContext::spellings`] as it was before ADR-132's option D: every
/// pattern expanded under every home and project spelling.
fn spelled_every_way(ctx: &EvalContext, raw: &str) -> Vec<String> {
    let (negated, body) = crate::pattern::split_negation(raw);
    let bang = if negated { "!" } else { "" };
    let moved = ctx.moved_dirs.iter().filter_map(|(default, dir)| {
        let rest = body.strip_prefix(default.as_str())?;
        (rest.is_empty() || rest.starts_with('/'))
            .then(|| format!("{bang}{}{rest}", paths::glob_literal(dir)))
    });
    let raws: Vec<String> = std::iter::once(raw.to_owned()).chain(moved).collect();
    let projects: Vec<Option<&str>> = match &ctx.project {
        Some(p) => [Some(p), ctx.real_project.as_ref()]
            .into_iter()
            .flatten()
            .map(|p| Some(p.as_str()))
            .collect(),
        None => vec![None],
    };
    let mut out = Vec::new();
    for home in [Some(&ctx.home), ctx.real_home.as_ref()]
        .into_iter()
        .flatten()
    {
        for project in &projects {
            out.extend(
                raws.iter()
                    .filter_map(|raw| paths::expand_pattern(raw, home, *project)),
            );
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Every word of `text` split at spaces, quotes, brackets and commas that
/// could name a place (a `~`, `${project}` or a leading `/`, `!` or `*`):
/// what a policy or fixture file spells patterns with, and more, which only
/// adds inputs to compare on.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '[' | ']' | ','))
        .filter(|w| w.contains('~') || w.contains("${project}") || w.starts_with(['/', '!', '*']))
}

/// Contexts besides the samples where the home and project spellings differ
/// in what a pattern can name: a resolved home with another user name (so
/// `~me/…` expands under one spelling only), a home that spells
/// `${project}`, no project, and a project in the home.
fn odd_contexts() -> Vec<EvalContext> {
    let base = EvalContext {
        home: "/Users/me".into(),
        project: Some("/Users/me/p".into()),
        real_home: Some("/Volumes/d/other".into()),
        real_project: Some("/Volumes/d/other/p".into()),
        moved_dirs: vec![("~/.codex".into(), "~/moved".into())],
        cwd: "/Users/me/p".into(),
        case_insensitive_paths: true,
    };
    vec![
        EvalContext {
            home: "/h/${project}".into(),
            real_home: Some("/r/${project}/me".into()),
            ..base.clone()
        },
        EvalContext {
            project: None,
            real_project: None,
            ..base.clone()
        },
        EvalContext {
            real_project: None,
            ..base.clone()
        },
        base,
    ]
}

/// The spellings of every pattern of the default policy and every word of
/// the conformance fixtures, in every context, are the set every home and
/// project spelling gave (ADR-132, option D).
#[test]
fn spellings_are_the_set_every_combination_gives() {
    let policy = Policy::parse(crate::DEFAULT_POLICY).unwrap();
    let mut raws: Vec<String> = policy
        .deny
        .iter()
        .chain(&policy.repo_review)
        .chain(&policy.allow)
        .chain(&policy.review)
        .chain(&policy.defer)
        .flat_map(|g| {
            Kind::ALL
                .iter()
                .flat_map(|k| g.patterns(*k).iter().cloned())
        })
        .collect();
    for text in [
        crate::DEFAULT_POLICY,
        include_str!("../../../../../tests/conformance/attacks.yaml"),
        include_str!("../../../../../tests/conformance/benign.yaml"),
        include_str!("../../../../../tests/conformance/review.yaml"),
    ] {
        raws.extend(words(text).map(str::to_owned));
    }
    raws.extend(
        [
            "~",
            "~/",
            "!~",
            "~me",
            "~me/.ssh/**",
            "~other/x",
            "~a$b/x",
            "x~",
            "!~/.ssh/**",
            "${project}",
            "!${project}/.git/**",
            "~/${project}",
            "/a/${project}/b",
            "~/.codex",
            "~/.codex/auth.json",
            "!~/.codex/**",
            "~/.codexx",
            "~/.claude/x",
            "",
        ]
        .map(str::to_owned),
    );
    raws.sort();
    raws.dedup();
    let mut compared = 0;
    for ctx in sample_contexts().into_iter().chain(odd_contexts()) {
        for raw in &raws {
            assert_eq!(
                ctx.spellings(raw),
                spelled_every_way(&ctx, raw),
                "{raw:?} {ctx:?}"
            );
            compared += 1;
        }
    }
    assert!(compared > 20_000, "{compared}");
}

/// Contexts the engine's tests spell and compile patterns for: a home of 9,
/// 30 and 120 characters, the last also with resolved spellings of the home
/// and project (`/private/var/…`, as `openmoat bench`'s throwaway home on
/// macOS had), with and without moved directories, in both case modes.
pub(crate) fn sample_contexts() -> Vec<EvalContext> {
    let long = format!("/var/folders/{}/T/moat-bench/home", "x".repeat(87));
    let homes = [
        ("/Users/me".to_owned(), None),
        (format!("/Users/{}", "n".repeat(23)), None),
        (long.clone(), None),
        (long.clone(), Some(format!("/private{long}"))),
    ];
    let mut out = Vec::new();
    for (home, real_home) in homes {
        for moved in [false, true] {
            for case_insensitive_paths in [false, true] {
                let project = format!("{home}/proj");
                let moved_dirs = if moved {
                    vec![
                        ("~/.codex".to_owned(), "/srv/codex".to_owned()),
                        ("~/.claude".to_owned(), format!("{home}/elsewhere/claude")),
                    ]
                } else {
                    Vec::new()
                };
                out.push(EvalContext {
                    real_project: real_home.as_ref().map(|r| format!("{r}/proj")),
                    real_home: real_home.clone(),
                    cwd: project.clone(),
                    project: Some(project),
                    home: home.clone(),
                    moved_dirs,
                    case_insensitive_paths,
                });
            }
        }
    }
    out
}

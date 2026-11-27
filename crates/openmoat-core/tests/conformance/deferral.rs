//! Every conformance fixture decided by compiles that build their globs at
//! different times (ADR-132): every glob at compile, the texts that cannot
//! fail to parse on first use (what `CompiledPolicy::compile` does), and every
//! glob on first use. The verdicts, rules and reasons must be the same.

use openmoat_core::{
    Action, CompiledPolicy, DEFAULT_POLICY, Decision, EvalContext, GlobBuilds, InjectedMap,
    MapPathResolver, MapResolver, Policy, RepoPolicy, Staging, Taint,
};

use super::{decoys, load_fixtures, repo_root, worst::worst_taint};

const MODES: [GlobBuilds; 3] = [
    GlobBuilds::AtCompile,
    GlobBuilds::OnFirstUse,
    GlobBuilds::EveryOnFirstUse,
];

#[test]
fn every_fixture_decides_alike_whenever_its_globs_are_built() {
    let policy = Policy::parse(DEFAULT_POLICY).expect("default policy must lint");
    let base = EvalContext {
        home: "/Users/me".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    };
    let shared = MODES.map(|builds| {
        CompiledPolicy::compile_owned_building(policy.clone(), &base, builds)
            .expect("default policy must compile")
    });
    let fixtures = load_fixtures(&repo_root().join("tests/conformance"));
    assert!(fixtures.len() > 500, "{}", fixtures.len());
    for (_, fixture) in fixtures {
        let resolver = MapResolver {
            resolved: fixture.resolve.clone(),
            pins: fixture.pins.clone(),
        };
        let links = MapPathResolver {
            links: fixture.links.clone(),
            files: fixture.files.clone(),
        };
        let merged = fixture.repo.as_ref().map(|r| {
            RepoPolicy::parse(&r.policy)
                .and_then(|repo| repo.merge(&policy, r.trusted))
                .unwrap_or_else(|e| panic!("{}: repo policy: {e}", fixture.id))
        });
        let guarded = decoys::guarded(merged.as_ref().unwrap_or(&policy), fixture.decoys.as_ref());
        let used = guarded.as_ref().or(merged.as_ref()).unwrap_or(&policy);
        let ctx = fixture.context.as_ref().map_or_else(
            || base.clone(),
            |c| EvalContext {
                cwd: c.cwd.clone(),
                project: c.project.clone(),
                real_project: c.real_project.clone(),
                real_home: c.real_home.clone(),
                moved_dirs: c.moved_dirs.clone().into_iter().collect(),
                case_insensitive_paths: c.case_insensitive_paths,
                ..base.clone()
            },
        );
        let arguments = fixture.action.arguments();
        let action = fixture.action.into_action(&fixture.id);
        let session: Vec<(Action, Option<String>)> = fixture
            .session
            .into_iter()
            .enumerate()
            .map(|(n, mut earlier)| {
                let output = earlier.output.take();
                (
                    earlier.into_action(&format!("{}.session[{n}]", fixture.id)),
                    output,
                )
            })
            .collect();
        // Fixtures on the default policy and context share one compile per
        // mode, as `default_policy_conformance` shares one: a glob an earlier
        // fixture built is then already built, as in a long-lived engine.
        let shared_ctx = fixture.context.is_none() && merged.is_none() && guarded.is_none();
        let own = (!shared_ctx).then(|| {
            MODES.map(|builds| {
                CompiledPolicy::compile_owned_building(used.clone(), &ctx, builds)
                    .expect("the policy compiles")
            })
        });
        let compiles = own.as_ref().unwrap_or(&shared);
        let decide = |compiled: &CompiledPolicy<'static>| -> (Decision, Decision) {
            let plain = compiled.decide_with(&action, &resolver, &links);
            let worst = compiled.with_taint(plain.clone(), &action, &links, &worst_taint());
            let worst = compiled.with_trifecta(worst, &action, &links, &worst_taint());
            let (mut taint, mut staging) = (Taint::default(), Staging::default());
            let mut seen = InjectedMap::default();
            for (earlier, output) in &session {
                let (exposure, collection) =
                    compiled.exposure_and_collection(earlier, &ctx.cwd, &links, &|_| false);
                taint.absorb(exposure);
                staging.absorb(collection);
                if let (Some(output), Some(source)) =
                    (output, compiled.output_source(earlier, &ctx.cwd, &links))
                {
                    seen.add(compiled.injected_tokens(earlier, &ctx.cwd, output), &source);
                }
            }
            let decision = compiled.with_injected(plain, &action, &links, &seen);
            let decision = compiled.with_arguments(decision, &action, &links, &arguments, &seen);
            let decision = compiled.with_taint(decision, &action, &links, &taint);
            let decision = compiled.with_staging(decision, &action, &links, &staging, &|_| false);
            let decision = compiled.with_trifecta(decision, &action, &links, &taint);
            assert_eq!(compiled.unbuilt(), None, "{}", fixture.id);
            (decision, worst)
        };
        let [at_compile, rest @ ..] = compiles.each_ref().map(decide);
        for other in rest {
            assert_eq!(other, at_compile, "{}", fixture.id);
        }
    }
}

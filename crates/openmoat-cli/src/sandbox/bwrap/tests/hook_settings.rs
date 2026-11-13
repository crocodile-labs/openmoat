//! The agents' hook settings a project lacks when the session starts
//! (`bwrap/hook_settings.rs`).

use super::super::{Mount, hook_settings, missing_hook_settings, project_masks};
use super::session_ir;

/// The hook settings `kernel-self` protects in a project are the default
/// policy's nested write denials: the files each agent reads its hooks (and
/// `disableAllHooks`) from.
#[test]
fn the_protected_hook_settings_are_each_agents() {
    let ir = session_ir("/work/p");
    let protected = hook_settings::protected(&ir);
    for expected in [
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".gemini/settings.json",
        ".github/copilot/settings.json",
        ".github/copilot/settings.local.json",
        ".codex/hooks.json",
        ".cursor/hooks.json",
        ".copilot/hooks",
    ] {
        assert!(
            protected.iter().any(|p| p == expected),
            "{expected}: {protected:?}"
        );
    }
}

/// A hook settings file missing when the session starts is planned as a
/// read-only placeholder (`{}` for JSON), with each missing folder above it
/// created and pinned first; one that exists, or one below a file or a link,
/// is left out.
#[test]
fn missing_hook_settings_get_read_only_placeholders() {
    use hook_settings::{Found, plan};

    let ir = session_ir("/p");
    let exists = |present: &'static [&'static str], other: &'static [&'static str]| {
        move |path: &str| {
            let rel = path.strip_prefix("/p/").unwrap_or(path);
            if present.contains(&rel) {
                Found::Dir
            } else if other.contains(&rel) {
                Found::Other
            } else {
                Found::Missing
            }
        }
    };
    let dir_below = |path: &str| path.ends_with("/.copilot/hooks");
    // `.claude` exists with its settings; `.cursor` is a link; `.github` exists.
    let found = exists(
        &[".claude", ".github"],
        &[".claude/settings.json", ".cursor"],
    );
    let out = plan(&ir, "/p", &found, &dir_below);
    let file = |rel: &str, contents| hook_settings::Placeholder {
        path: format!("/p/{rel}"),
        dir: false,
        contents,
    };
    let folder = |rel: &str| hook_settings::Placeholder {
        path: format!("/p/{rel}"),
        dir: true,
        contents: "",
    };
    for expected in [
        file(".claude/settings.local.json", "{}"),
        folder(".gemini"),
        file(".gemini/settings.json", "{}"),
        folder(".github/copilot"),
        file(".github/copilot/settings.local.json", "{}"),
        folder(".codex"),
        file(".codex/hooks.json", "{}"),
        folder(".copilot"),
        folder(".copilot/hooks"),
    ] {
        assert!(
            out.placeholders.contains(&expected),
            "{expected:?}: {:#?}",
            out.placeholders
        );
    }
    let paths: Vec<&str> = out.placeholders.iter().map(|p| p.path.as_str()).collect();
    for left in ["/p/.claude", "/p/.claude/settings.json", "/p/.github"] {
        assert!(!paths.contains(&left), "{left} exists: {paths:?}");
    }
    assert!(
        !paths.iter().any(|p| p.starts_with("/p/.cursor")),
        "below a link: {paths:?}"
    );
    // each folder once, before what is inside it
    let at = |p: &str| paths.iter().position(|x| *x == p).unwrap();
    assert!(at("/p/.gemini") < at("/p/.gemini/settings.json"));
    assert!(at("/p/.copilot") < at("/p/.copilot/hooks"));
    assert_eq!(
        paths.iter().filter(|p| **p == "/p/.github/copilot").count(),
        1
    );
    // folders bound onto themselves first, then the files read-only
    let first_file = out
        .mounts
        .iter()
        .position(|m| matches!(m, Mount::ReadOnly(_)))
        .unwrap();
    assert!(
        out.mounts[..first_file]
            .iter()
            .all(|m| matches!(m, Mount::ReadWrite(_)))
    );
    for expected in [
        Mount::ReadWrite("/p/.gemini".into()),
        Mount::ReadOnly("/p/.gemini/settings.json".into()),
        Mount::ReadOnly("/p/.claude/settings.local.json".into()),
        Mount::ReadOnly("/p/.copilot/hooks".into()),
    ] {
        assert!(
            out.mounts.contains(&expected),
            "{expected:?}: {:?}",
            out.mounts
        );
    }
    // nothing is planned where every one exists
    let all = |_: &str| Found::Dir;
    assert_eq!(
        plan(&ir, "/p", &all, &dir_below),
        hook_settings::Plan::default()
    );
}

/// The network namespace plans them for a real project, under each of its
/// spellings for the mounts and the resolved one for the files made; without
/// a namespace the same paths are the ones `moat run` watches.
#[test]
fn the_network_namespace_plans_the_missing_hook_settings_of_a_project() {
    let dir = tempfile::tempdir().unwrap();
    let real = std::fs::canonicalize(dir.path()).unwrap();
    let project = real.display().to_string();
    let ir = session_ir(&project);
    let masks = project_masks(&ir, &[project.clone(), "/other/p".into()]).unwrap();
    let gemini = format!("{project}/.gemini/settings.json");
    assert!(
        masks.mounts.contains(&Mount::ReadOnly(gemini.clone())),
        "{masks:?}"
    );
    assert!(
        masks
            .mounts
            .contains(&Mount::ReadOnly("/other/p/.gemini/settings.json".into())),
        "{masks:?}"
    );
    assert!(
        masks
            .placeholders
            .iter()
            .all(|p| p.path.starts_with(&project)),
        "{masks:?}"
    );
    assert!(masks.placeholders.iter().any(|p| p.path == gemini));
    let watched = missing_hook_settings(&ir, std::slice::from_ref(&project));
    assert!(watched.contains(&gemini), "{watched:?}");
    assert!(
        watched.iter().all(|p| !p.ends_with("/.gemini")),
        "{watched:?}"
    );
    assert_eq!(missing_hook_settings(&ir, &[]), Vec::<String>::new());
}

/// A folder of an agent's configuration missing where its holder exists, or
/// is made for the hook settings, is planned as an empty read-only folder
/// (ADR-089): a mount over a folder covers a hook written in it after the
/// start. None where the policy lets commands write below it, where it
/// exists, or where its holder is missing and not made anyway.
#[test]
fn missing_agent_configuration_folders_become_read_only_folders() {
    use hook_settings::{Found, plan};

    let ir = session_ir("/p");
    let found = |path: &str| match path.strip_prefix("/p/").unwrap_or(path) {
        ".claude" | ".github" | ".opencode" | ".opencode/tools" => Found::Dir,
        _ => Found::Missing,
    };
    let denied = [
        "/p/.claude/hooks",
        "/p/.github/hooks",
        "/p/.pi/extensions",
        "/p/.opencode/tools",
        "/p/.copilot/hooks",
    ];
    let dir_below = |path: &str| denied.contains(&path);
    let out = plan(&ir, "/p", &found, &dir_below);
    let folders: Vec<&str> = out
        .placeholders
        .iter()
        .filter(|p| p.dir)
        .map(|p| p.path.as_str())
        .collect();
    for made in ["/p/.claude/hooks", "/p/.github/hooks"] {
        assert!(folders.contains(&made), "{made}: {folders:?}");
        assert!(
            out.mounts.contains(&Mount::ReadOnly(made.to_owned())),
            "{made}: {:?}",
            out.mounts
        );
    }
    // `.pi` is missing and nothing makes it; `.opencode/tools` exists;
    // `.opencode/plugins` is not denied below here.
    for left in [
        "/p/.pi",
        "/p/.pi/extensions",
        "/p/.opencode/tools",
        "/p/.opencode/plugins",
    ] {
        assert!(!folders.contains(&left), "{left}: {folders:?}");
    }
    let each = |p: &str| folders.iter().filter(|x| **x == p).count();
    assert_eq!(each("/p/.copilot/hooks"), 1, "once: {folders:?}");
}

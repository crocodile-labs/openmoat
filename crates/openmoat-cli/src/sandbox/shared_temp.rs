//! The shared temp directories, left out of what `moat run`'s commands read.
//!
//! The default policy lists them in `sandbox.read_roots` for the host
//! sandboxes, whose commands use them as their temp directory. `moat run`
//! gives each run a temp directory of its own (`commands/run/temp.rs`) and
//! no command there can write the shared ones, so what a build reads back is in
//! its own: the shared ones hold only what other programs and sessions left.
//!
//! On macOS `/var/folders/<xx>/<id>/` is three folders. `T` is the temp
//! directory, and goes. `C` (the per-user cache: compilers' module caches,
//! Metal shaders) and `0` (the per-user directory: the Launch Services
//! database) are read by system libraries and Apple's tools whatever `TMPDIR`
//! says, so they stay.
//!
//! The roots go from the sandbox's copy of the policy only: the hook goes on
//! deciding with the whole of it. Under `--isolate` the shared temp directory is
//! an empty `tmpfs` already, and this is not used.

use openmoat_core::Policy;

/// The roots left out, as the default policy lists them.
const SHARED: [&str; 4] = [
    "/tmp",
    "/private/tmp",
    "/var/folders",
    "/private/var/folders",
];

/// The roots that hold the per-user folders on macOS.
const PER_USER: [&str; 2] = ["/var/folders", "/private/var/folders"];

/// What macOS keeps of them, as Seatbelt sees the path (`/var` is a link).
/// `read_roots` in a policy file are never globs; these are the sandbox's own.
const MACOS_KEPT: [&str; 2] = ["/private/var/folders/*/*/C", "/private/var/folders/*/*/0"];

/// `policy` for `moat run`'s sandbox: without [`SHARED`] in its read roots and,
/// on `macos`, with [`MACOS_KEPT`] where it listed [`PER_USER`]. A folder below
/// them that a person listed stays, as does every other root.
pub fn for_run(policy: &mut Policy, macos: bool) {
    let Some(settings) = policy.sandbox.as_mut() else {
        return;
    };
    let named = |root: &str, list: &[&str]| list.contains(&root.trim_end_matches('/'));
    let per_user = settings.read_roots.iter().any(|r| named(r, &PER_USER));
    settings.read_roots.retain(|root| !named(root, &SHARED));
    if macos && per_user {
        settings.read_roots.extend(MACOS_KEPT.map(str::to_owned));
    }
}

#[cfg(test)]
mod tests {
    use openmoat_core::{DEFAULT_POLICY, EvalContext};

    use super::*;
    use crate::sandbox::{Grants, landlock_rules, seatbelt_profile};

    fn narrowed(macos: bool) -> Policy {
        let mut policy = Policy::parse(DEFAULT_POLICY).unwrap();
        for_run(&mut policy, macos);
        policy
    }

    fn context() -> EvalContext {
        EvalContext {
            home: "/Users/me".into(),
            project: Some("/Users/me/proj".into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: "/Users/me/proj".into(),
            case_insensitive_paths: false,
        }
    }

    fn grants(tmpdir: &str) -> Grants {
        Grants {
            tmpdir: Some(tmpdir.into()),
            ..Grants::default()
        }
    }

    #[test]
    fn linux_commands_read_no_shared_temp_but_their_own() {
        let run = "/tmp/openmoat-run-1";
        let rules = landlock_rules(&narrowed(false), &context(), grants(run))
            .unwrap()
            .rules;
        for shared in SHARED {
            assert!(!rules.read.iter().any(|r| r == shared), "{shared}");
            assert!(!rules.write.iter().any(|w| w == shared), "{shared}");
        }
        assert!(rules.write.iter().any(|w| w == run), "{:?}", rules.write);
        assert!(rules.read.iter().any(|r| r == "/usr"), "{:?}", rules.read);
    }

    #[test]
    fn macos_keeps_the_per_user_caches_and_loses_the_temp_folder() {
        let run = "/private/var/folders/xy/id/T/openmoat-run-1";
        let profile = seatbelt_profile(&narrowed(true), &context(), grants(run))
            .unwrap()
            .profile;
        for gone in [
            "/tmp",
            "/private/tmp",
            "/var/folders",
            "/private/var/folders",
        ] {
            let subpath = format!("(subpath \"{gone}\")");
            assert!(!profile.contains(&subpath), "{subpath}\n{profile}");
        }
        for kept in ["C", "0"] {
            let regex = format!("(regex \"^/private/var/folders/[^/]*/[^/]*/{kept}(/.*)?$\")");
            assert!(profile.contains(&regex), "{regex}\n{profile}");
        }
        assert!(!profile.contains("[^/]*/T"), "{profile}");
        assert!(
            profile.contains(&format!("(subpath \"{run}\")")),
            "{profile}"
        );
    }

    #[test]
    fn only_the_shared_roots_go() {
        let yaml =
            "version: 1\nsandbox:\n  read_roots: ['/usr', '/tmp/', '/tmp/kept', '~/.cargo']\n";
        let mut policy = Policy::parse(yaml).unwrap();
        for_run(&mut policy, true);
        // No `/var/folders` listed, so nothing of it is added.
        assert_eq!(
            policy.sandbox.unwrap().read_roots,
            ["/usr", "/tmp/kept", "~/.cargo"]
        );
        let mut bare = Policy::parse("version: 1\n").unwrap();
        for_run(&mut bare, true);
        assert_eq!(bare.sandbox, None);
    }
}

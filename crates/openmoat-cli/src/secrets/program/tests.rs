use super::*;

#[test]
fn paths_under_the_home_are_written_as_policy_rules_name_them() {
    assert_eq!(
        policy_form("/Users/me/sdk/bin/x", "/Users/me"),
        "~/sdk/bin/x"
    );
    assert_eq!(policy_form("/Users/me2/x", "/Users/me"), "/Users/me2/x");
    assert_eq!(policy_form("/usr/bin/x", "/Users/me/"), "/usr/bin/x");
}

/// Stand-in programs (`stand.rs`).
#[cfg(unix)]
mod programs {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use openmoat_core::Policy;

    use super::*;
    use crate::secrets::stand::Stand;

    #[test]
    fn a_system_program_is_kept_by_the_system_and_a_users_file_is_not() {
        // `/bin/sh` and every folder above it belong to root on macOS and Linux.
        assert!(admin_only(Path::new("/bin/sh")));
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x");
        std::fs::write(&file, "").unwrap();
        assert!(!admin_only(&file));
    }

    /// An executable file `rel` under the stand's folder with `text`.
    fn put(stand: &Stand, rel: &str, text: &str) -> String {
        let path = Path::new(&stand.root).join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn denying(rules: &[String]) -> Policy {
        let list = rules
            .iter()
            .map(|r| format!("'{r}'"))
            .collect::<Vec<_>>()
            .join(", ");
        Policy::parse(&format!(
            "version: 1\ndeny:\n  - id: credential-programs\n    fs.write: [{list}]\n"
        ))
        .unwrap()
    }

    /// Attack: the policy covers the program file only, so the agent can put
    /// files beside it (an interpreter, a library it loads), or rename its
    /// folder and put another in its place. Every folder above it, below
    /// the home, must be covered with what it holds.
    #[test]
    fn every_folder_above_the_program_is_checked() {
        let stand = Stand::new();
        let file = put(&stand, "sdk/bin/tool", "\x7fELF");
        let only_file = denying(std::slice::from_ref(&file));
        let error = format!(
            "{:#}",
            check(&file, &only_file, &stand.root, &[]).err().unwrap()
        );
        assert!(error.contains("could be changed by the agent"), "{error}");
        // The highest open folder is named, as a rule for all below it.
        assert!(error.contains("\"~/sdk/**\""), "{error}");
        // The program's own folder alone is not enough either.
        let bin = denying(&[format!("{}/sdk/bin/**", stand.root)]);
        let error = format!("{:#}", check(&file, &bin, &stand.root, &[]).err().unwrap());
        assert!(error.contains("\"~/sdk/**\""), "{error}");
        let all = denying(&[format!("{}/sdk/**", stand.root)]);
        let checked = check(&file, &all, &stand.root, &[]).unwrap();
        assert_eq!(checked.path, std::fs::canonicalize(&file).unwrap());
        assert!(checked.interpreter.is_none());
    }

    /// Attack: `#!/usr/bin/env python3` looks the interpreter up in a search
    /// path, so a planted `python3` would run in its place; an interpreter
    /// the agent could change is not checked by the program's pin.
    #[test]
    fn a_script_needs_an_interpreter_the_agent_cannot_change() {
        let stand = Stand::new();
        let env = put(&stand, "env-script", "#!/usr/bin/env python3\nprint(1)\n");
        let error = format!(
            "{:#}",
            check(&env, &stand.policy, &stand.root, &[]).err().unwrap()
        );
        assert!(error.contains("/usr/bin/env"), "{error}");
        assert!(error.contains("search path"), "{error}");
        let bare = put(&stand, "bare-script", "#! python3\n");
        let error = format!(
            "{:#}",
            check(&bare, &stand.policy, &stand.root, &[]).err().unwrap()
        );
        assert!(error.contains("full path"), "{error}");
        // An interpreter outside every deny rule, in a folder of the person's.
        let elsewhere = crate::secrets::stand::scratch();
        let interp = elsewhere.path().join("python3");
        std::fs::write(&interp, "\x7fELF").unwrap();
        std::fs::set_permissions(&interp, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = put(
            &stand,
            "user-interp",
            &format!("#!{} -u\n", interp.display()),
        );
        let error = format!(
            "{:#}",
            check(&script, &stand.policy, &stand.root, &[])
                .err()
                .unwrap()
        );
        assert!(error.contains("the interpreter of"), "{error}");
        assert!(error.contains("could be changed by the agent"), "{error}");
        // An interpreter that is a script itself.
        let inner = put(&stand, "inner", "#!/bin/sh\n");
        let outer = put(&stand, "outer", &format!("#!{inner}\n"));
        let error = format!(
            "{:#}",
            check(&outer, &stand.policy, &stand.root, &[])
                .err()
                .unwrap()
        );
        assert!(error.contains("a script itself"), "{error}");
        // `/bin/sh` is kept by the system: the script passes, pinned with it.
        let ok = put(&stand, "ok", "#!/bin/sh\necho x\n");
        let checked = check(&ok, &stand.policy, &stand.root, &[]).unwrap();
        assert_eq!(
            checked.interpreter,
            Some(std::fs::canonicalize("/bin/sh").unwrap())
        );
    }

    /// Attack: the agent writes a repository policy whose deny rule covers a
    /// program it put in place; under `openmoat run` that rule is merged into
    /// the proxy's policy. Only the person's own rules count.
    #[test]
    fn a_repository_deny_rule_is_no_proof() {
        let stand = Stand::new();
        let file = put(&stand, "token", "\x7fELF");
        assert!(check(&file, &stand.policy, &stand.root, &[]).is_ok());
        let mut merged = stand.policy.clone();
        merged.deny[0].id = format!("{}credential-programs", openmoat_core::REPO_RULE_PREFIX);
        let error = format!(
            "{:#}",
            check(&file, &merged, &stand.root, &[]).err().unwrap()
        );
        assert!(error.contains("could be changed by the agent"), "{error}");
    }

    /// Attack: the program sits in the project, which the agent's sandbox
    /// lets it write. Landlock cannot hold a deny rule inside a folder it
    /// grants, so the rule is no proof there; only root ownership is.
    #[test]
    fn a_deny_rule_inside_a_folder_the_sandbox_grants_is_no_proof() {
        let stand = Stand::new();
        let file = put(&stand, "project/tools/token", "\x7fELF");
        let project = format!("{}/project", stand.root);
        assert!(check(&file, &stand.policy, &stand.root, &[]).is_ok());
        for granted in [project.clone(), format!("{project}/tools")] {
            let error = format!(
                "{:#}",
                check(
                    &file,
                    &stand.policy,
                    &stand.root,
                    std::slice::from_ref(&granted)
                )
                .err()
                .unwrap()
            );
            assert!(error.contains("could be changed by the agent"), "{error}");
            assert!(error.contains(&format!("is in {granted}")), "{error}");
        }
        // A folder beside it with a longer name is not inside it.
        let beside = [format!("{}/proj", stand.root)];
        assert!(check(&file, &stand.policy, &stand.root, &beside).is_ok());
        // A system program in a granted folder still passes on its ownership.
        assert!(check("/bin/sh", &stand.policy, &stand.root, &["/bin".to_owned()]).is_ok());
    }
}

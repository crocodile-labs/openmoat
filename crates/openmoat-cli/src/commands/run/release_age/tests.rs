use std::path::PathBuf;

use super::{Found, NPM_BEFORE, ReleaseAge, UV_EXCLUDE_NEWER, UserConfig, env, user_config_path};

/// 2026-10-03 15:00 UTC.
const NOW: i64 = 1_790_985_600_000 + 15 * 3_600_000;

/// What [`env`] does for a week, with `inherited` set in the environment,
/// `files` (name, text) in the project and `user` (tool, text) in the
/// person's own configuration.
fn applied(inherited: &[&str], files: &[(&str, &str)], user: &[(UserConfig, &str)]) -> ReleaseAge {
    let found = Found {
        inherited: &|name| inherited.contains(&name).then(|| "x".to_owned()),
        project_has: &|file| files.iter().any(|(f, _)| *f == file),
        project_file: &|file| {
            files
                .iter()
                .find(|(f, _)| *f == file)
                .map(|(_, text)| (*text).to_owned())
        },
        user_file: &|tool| {
            user.iter()
                .find(|(t, _)| *t == tool)
                .map(|(_, text)| (*text).to_owned())
        },
    };
    env(7, NOW, &found)
}

/// The names [`env`] sets.
fn set(inherited: &[&str], files: &[(&str, &str)]) -> Vec<&'static str> {
    applied(inherited, files, &[])
        .vars
        .into_iter()
        .map(|(n, _)| n)
        .collect()
}

#[test]
fn both_tools_get_the_start_of_the_day_a_week_back() {
    let week = "2026-09-26T00:00:00Z".to_owned();
    let all = applied(&[], &[], &[]);
    assert_eq!(
        all.vars,
        [(NPM_BEFORE, week.clone()), (UV_EXCLUDE_NEWER, week)]
    );
    assert_eq!(all.notices, Vec::<String>::new());
    let off = Found {
        inherited: &|_| None,
        project_has: &|_| true,
        project_file: &|_| None,
        user_file: &|_| None,
    };
    assert_eq!(env(0, NOW, &off), ReleaseAge::default(), "0 days is off");
}

#[test]
fn the_persons_own_settings_are_kept() {
    assert_eq!(set(&["NPM_CONFIG_BEFORE"], &[]), [UV_EXCLUDE_NEWER]);
    assert_eq!(set(&[NPM_BEFORE], &[]), [UV_EXCLUDE_NEWER]);
    assert_eq!(set(&[UV_EXCLUDE_NEWER], &[]), [NPM_BEFORE]);
    let npmrc = (UserConfig::Npm, "registry=x\n before = 2099-01-01\n");
    let names = |user| -> Vec<&str> {
        applied(&[], &[], &[user])
            .vars
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    };
    assert_eq!(names(npmrc), [UV_EXCLUDE_NEWER]);
    assert_eq!(
        names((UserConfig::Uv, "exclude-newer = \"1 week\"\n")),
        [NPM_BEFORE]
    );
    // a comment in the person's uv.toml is no setting
    assert_eq!(
        names((UserConfig::Uv, "# exclude-newer = \"2099-01-01\"\n")),
        [NPM_BEFORE, UV_EXCLUDE_NEWER]
    );
}

/// The repository's files cannot switch the cut-off off: a later date, a
/// duration or a mention of the key in a comment leaves the policy's in place.
#[test]
fn the_projects_files_do_not_switch_the_cut_off_off() {
    for npmrc in [
        "before=2099-01-01\n",
        "before = 2099-01-01T00:00:00Z\n",
        "before=soon\n",
        "before-script=x\n",
    ] {
        assert_eq!(
            set(&[], &[(".npmrc", npmrc)]),
            [NPM_BEFORE, UV_EXCLUDE_NEWER],
            "{npmrc}"
        );
    }
    for (file, text) in [
        (
            "pyproject.toml",
            "[tool.uv]\nexclude-newer = \"2099-01-01\"\n",
        ),
        (
            "pyproject.toml",
            "# exclude-newer = \"2020-01-01\"\n[project]\n",
        ),
        (
            "pyproject.toml",
            "[project]\nexclude-newer = \"2020-01-01\"\n",
        ),
        ("pyproject.toml", "description = \"exclude-newer\"\n"),
        ("pyproject.toml", "not toml ["),
        ("uv.toml", "exclude-newer = \"1 week\"\n"),
        ("uv.toml", "exclude-newer = \"2099-01-01T00:00:00Z\"\n"),
    ] {
        assert_eq!(
            set(&[], &[(file, text)]),
            [NPM_BEFORE, UV_EXCLUDE_NEWER],
            "{file}: {text}"
        );
    }
}

/// A stricter cut-off in the project (an earlier day) is kept: the
/// variable would override it with a later one.
#[test]
fn a_stricter_cut_off_in_the_project_is_kept() {
    assert_eq!(
        set(&[], &[(".npmrc", "before=2026-01-01\n")]),
        [UV_EXCLUDE_NEWER]
    );
    let pyproject = (
        "pyproject.toml",
        "[tool.uv]\nexclude-newer = \"2026-01-01T00:00:00Z\"\n",
    );
    assert_eq!(set(&[], &[pyproject]), [NPM_BEFORE]);
    assert_eq!(
        set(&[], &[("uv.toml", "exclude-newer = \"2025-06-30\"\n")]),
        [NPM_BEFORE]
    );
    // the same day as the policy's is not stricter
    assert_eq!(
        set(&[], &[(".npmrc", "before=2026-09-26T12:00:00Z\n")]),
        [NPM_BEFORE, UV_EXCLUDE_NEWER]
    );
}

#[test]
fn a_uv_lockfile_keeps_uv_as_it_is_and_says_so() {
    let lock = applied(&[], &[("uv.lock", "")], &[]);
    let names: Vec<_> = lock.vars.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, [NPM_BEFORE]);
    assert_eq!(lock.notices.len(), 1, "{:?}", lock.notices);
    for expected in ["uv.lock", "7 days", "exclude-newer", UV_EXCLUDE_NEWER] {
        assert!(lock.notices[0].contains(expected), "{}", lock.notices[0]);
    }
    // the person's own cut-off needs no notice
    let own = applied(&[UV_EXCLUDE_NEWER], &[("uv.lock", "")], &[]);
    assert_eq!(own.notices, Vec::<String>::new());
}

#[test]
fn the_user_level_files_are_where_each_tool_looks() {
    let home = Some(PathBuf::from("/home/me"));
    let none = |_: &str| None;
    assert_eq!(
        user_config_path(UserConfig::Npm, &none, home.clone()),
        Some(PathBuf::from("/home/me/.npmrc"))
    );
    assert_eq!(
        user_config_path(UserConfig::Uv, &none, home.clone()),
        Some(PathBuf::from("/home/me/.config/uv/uv.toml"))
    );
    let moved = |name: &str| match name {
        "npm_config_userconfig" => Some("/cfg/npmrc".to_owned()),
        "XDG_CONFIG_HOME" => Some("/xdg".to_owned()),
        _ => None,
    };
    assert_eq!(
        user_config_path(UserConfig::Npm, &moved, home.clone()),
        Some(PathBuf::from("/cfg/npmrc"))
    );
    assert_eq!(
        user_config_path(UserConfig::Uv, &moved, home),
        Some(PathBuf::from("/xdg/uv/uv.toml"))
    );
    assert_eq!(user_config_path(UserConfig::Npm, &none, None), None);
}

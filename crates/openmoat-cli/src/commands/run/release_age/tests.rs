use super::{Found, NPM_BEFORE, UV_EXCLUDE_NEWER, env};

/// 2026-10-03 15:00 UTC.
const NOW: i64 = 1_790_985_600_000 + 15 * 3_600_000;

/// The names [`env`] sets for a week, with `inherited` set in the
/// environment and `files` (name, text) in the project.
fn set(inherited: &[&str], files: &[(&str, &str)]) -> Vec<&'static str> {
    let found = Found {
        inherited: &|name| inherited.contains(&name),
        project_has: &|file| files.iter().any(|(f, _)| *f == file),
        project_file: &|file| {
            files
                .iter()
                .find(|(f, _)| *f == file)
                .map(|(_, text)| (*text).to_owned())
        },
    };
    env(7, NOW, &found).into_iter().map(|(n, _)| n).collect()
}

#[test]
fn both_tools_get_the_start_of_the_day_a_week_back() {
    let found = Found {
        inherited: &|_| false,
        project_has: &|_| false,
        project_file: &|_| None,
    };
    let week = "2026-09-26T00:00:00Z".to_owned();
    assert_eq!(
        env(7, NOW, &found),
        [(NPM_BEFORE, week.clone()), (UV_EXCLUDE_NEWER, week)]
    );
    assert!(env(0, NOW, &found).is_empty(), "0 days is off");
}

#[test]
fn the_persons_own_settings_are_kept() {
    assert_eq!(set(&["NPM_CONFIG_BEFORE"], &[]), [UV_EXCLUDE_NEWER]);
    assert_eq!(set(&[NPM_BEFORE], &[]), [UV_EXCLUDE_NEWER]);
    assert_eq!(set(&[UV_EXCLUDE_NEWER], &[]), [NPM_BEFORE]);
    let npmrc = [(".npmrc", "registry=x\n before = 2026-01-01\n")];
    assert_eq!(set(&[], &npmrc), [UV_EXCLUDE_NEWER]);
    let other_key = [(".npmrc", "before-script=x\n")];
    assert_eq!(set(&[], &other_key), [NPM_BEFORE, UV_EXCLUDE_NEWER]);
    let pyproject = [(
        "pyproject.toml",
        "[tool.uv]\nexclude-newer = \"2026-01-01\"\n",
    )];
    assert_eq!(set(&[], &pyproject), [NPM_BEFORE]);
    assert_eq!(
        set(&[], &[("uv.toml", "exclude-newer = \"1 week\"\n")]),
        [NPM_BEFORE]
    );
}

#[test]
fn a_uv_lockfile_keeps_uv_as_it_is() {
    assert_eq!(set(&[], &[("uv.lock", "")]), [NPM_BEFORE]);
}

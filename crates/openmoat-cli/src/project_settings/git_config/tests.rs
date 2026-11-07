use std::fs;

use super::{program_keys, warnings};

/// The configuration `git clone` writes runs nothing.
#[test]
fn a_fresh_clone_sets_nothing_that_runs() {
    let text = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\
                \tlogallrefupdates = true\n\tignorecase = true\n\tprecomposeunicode = true\n\
                [remote \"origin\"]\n\turl = https://github.com/x/y.git\n\
                \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
                [branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n";
    assert_eq!(program_keys(text), Vec::<String>::new());
}

/// Each key that makes git run a program is named once, as git spells it.
#[test]
fn keys_that_run_a_program_are_named() {
    let text = "[core]\n\tfsMonitor = ./.git/x.sh\n\tpager = less\n\
                [core] sshCommand = ssh -o ProxyCommand=x\n\
                [alias]\n\tst = status\n\tco = !sh -c x\n\
                [filter \"crypt\"]\n\tsmudge = ./decrypt\n\
                [diff \"bin\"]\n\ttextconv = ./conv\n\
                [credential]\n\thelper = !./steal\n\
                [includeIf \"gitdir:/\"]\n\tpath = ../evil.cfg\n\
                [core]\n\tfsmonitor = ./other.sh\n";
    assert_eq!(
        program_keys(text),
        [
            "core.fsmonitor",
            "core.pager",
            "core.sshcommand",
            "alias.co",
            "filter.crypt.smudge",
            "diff.bin.textconv",
            "credential.helper",
            "includeif.gitdir:/.path",
        ]
    );
}

/// Values git treats as its own and not a program, and comments, name nothing.
#[test]
fn builtin_values_and_comments_name_nothing() {
    let text = "# [core] fsmonitor = ./x\n; alias.x = !y\n\
                [core]\n\tfsmonitor = true\n\tfsmonitor = false\n\thooksPath = .husky/_\n\
                \thooksPath = .githooks/\n\
                [filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\
                \tprocess = git-lfs filter-process\n\trequired = true\n\
                [credential]\n\thelper = osxkeychain\n\thelper = \n\
                [pager]\n\tlog = false\n";
    assert_eq!(program_keys(text), Vec::<String>::new());
}

/// A hooks folder elsewhere, quoted values, old-style subsections and inline
/// comments are read as git reads them.
#[test]
fn spellings_git_accepts_are_read() {
    let text = "[core]\n\thooksPath = \"/tmp/hooks\" ; planted\n\
                [diff.tool]\n\tcommand = ./x\n\
                [pager]\n\tdiff = ./p # comment\n";
    assert_eq!(
        program_keys(text),
        ["core.hookspath", "diff.tool.command", "pager.diff"]
    );
}

/// `doctor` and `status` name the repository's own `.git/config`, a linked
/// worktree's file and the main repository's, and a file too large to read.
#[test]
fn the_repository_files_are_found() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    assert_eq!(warnings(&project, &user_home), Vec::<String>::new());

    fs::write(
        project.join(".git/config"),
        "[core]\n\tfsmonitor = .git/hooks/x\n",
    )
    .unwrap();
    let found = warnings(&project, &user_home);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("config: sets core.fsmonitor,"),
        "{found:?}"
    );

    let worktree = user_home.join("wt");
    let gitdir = project.join(".git/worktrees/wt");
    fs::create_dir_all(&gitdir).unwrap();
    fs::create_dir_all(&worktree).unwrap();
    fs::write(
        worktree.join(".git"),
        format!("gitdir: {}\n", gitdir.display()),
    )
    .unwrap();
    fs::write(gitdir.join("commondir"), "../..\n").unwrap();
    fs::write(gitdir.join("config.worktree"), "[alias]\n\tx = !y\n").unwrap();
    let found = warnings(&worktree, &user_home);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].contains("core.fsmonitor"), "{found:?}");
    assert!(
        found[1].contains("config.worktree: sets alias.x,"),
        "{found:?}"
    );

    let padded = format!("[core]\n\tfsmonitor = ./x\n{}", "#".repeat(1024 * 1024));
    fs::write(project.join(".git/config"), padded).unwrap();
    let found = warnings(&project, &user_home);
    assert!(found[0].contains("not read"), "{found:?}");
}

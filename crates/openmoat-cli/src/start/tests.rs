use super::*;

fn dirs() -> (tempfile::TempDir, Home, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    // `.moat` is the default's name; any name will do, and some sandboxes
    // refuse to create one.
    let home = Home::at(dir.path().join("me/state"));
    let user = dir.path().join("me");
    fs::create_dir_all(home.root()).unwrap();
    (dir, home, user)
}

fn run(program: &'static str) -> RunCommand {
    RunCommand {
        start: "openmoat run",
        writes: vec![PathBuf::from("/Users/me/.gemini")],
        program,
        args: &[],
    }
}

/// An executable named `name` in `dir`.
#[cfg(unix)]
fn program(dir: &Path, name: &str) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    crate::home::write_private_program(&path, b"#!/bin/sh\n").unwrap();
    path
}

#[test]
fn a_shim_runs_openmoat_run_around_the_real_program_by_absolute_paths() {
    let shim = Shim::new(
        Host::GeminiCli,
        Path::new("/opt/openmoat/bin/openmoat"),
        Path::new("/opt/homebrew/bin/gemini"),
        &run("gemini"),
    );
    assert_eq!(shim.name, "gemini");
    assert!(shim.text.starts_with("#!/bin/sh\n"), "{}", shim.text);
    assert!(
        shim.text.ends_with(
            "exec '/opt/openmoat/bin/openmoat' run --write '/Users/me/.gemini' -- \
             '/opt/homebrew/bin/gemini' \"$@\"\n"
        ),
        "{}",
        shim.text
    );
    assert!(shim.text.contains("openmoat uninstall"), "{}", shim.text);
    // A quote in a path stays one word.
    assert_eq!(shim::quote("/a b/o'x"), "'/a b/o'\\''x'");
}

#[cfg(unix)]
#[test]
fn the_real_program_is_found_outside_the_shim_directory_and_never_the_shim() {
    let (dir, home, _user) = dirs();
    let shims = shim_dir(&home);
    let bin = dir.path().join("bin");
    program(&shims, "gemini");
    let real = program(&bin, "gemini");
    let path = vec![shims.clone(), bin];
    let here = RunHere::for_test();
    let offers = offers(
        &home,
        Path::new("/opt/openmoat"),
        &[Host::GeminiCli, Host::ClaudeCode],
        &path,
        &here,
    )
    .unwrap();
    // Claude Code has an OS sandbox of its own: no `openmoat run` command.
    let hosts: Vec<Host> = offers.iter().map(|s| s.host).collect();
    assert_eq!(hosts, [Host::GeminiCli]);
    assert_eq!(offers[0].program, real);

    write(&home, &offers).unwrap();
    let rows = report(&home, &path).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, Starts::Sandboxed);
    // Not offered again once written.
    assert_eq!(
        super::offers(&home, Path::new("/x"), &[Host::GeminiCli], &path, &here).unwrap(),
        []
    );
    assert_eq!(pinned_files(&home), [shims.join("gemini")]);

    // The search path without the shim directory starts it outside.
    let outside = report(&home, &path[1..]).unwrap();
    assert_eq!(outside[0].1, Starts::Outside(real.clone()));
    assert!(outside[0].1.needs_attention());
    // A changed shim is said to be one.
    fs::write(shims.join("gemini"), "#!/bin/sh\nexec evil\n").unwrap();
    assert_eq!(report(&home, &path).unwrap()[0].1, Starts::ShimChanged);
    let (removed, rc) = remove(&home, &[Host::GeminiCli]).unwrap();
    assert_eq!(removed, [Removed::Changed(shims.join("gemini"))]);
    assert!(shims.join("gemini").exists());
    assert_eq!(rc, None);
    assert_eq!(Record::load(&home).unwrap().shims, []);
}

#[cfg(unix)]
#[test]
fn uninstall_removes_each_shim_as_written_and_the_line_with_the_last() {
    let (dir, home, user) = dirs();
    let bin = dir.path().join("bin");
    program(&bin, "gemini");
    program(&bin, "opencode");
    let path = vec![bin];
    let here = RunHere::for_test();
    let hosts = [Host::GeminiCli, Host::OpenCode];
    let shims = offers(&home, Path::new("/opt/openmoat"), &hosts, &path, &here).unwrap();
    assert_eq!(shims.len(), 2);
    write(&home, &shims).unwrap();
    let zshrc = user.join(".zshrc");
    fs::write(&zshrc, "alias ll='ls -l'").unwrap();
    let lines = rc::lines(&shim_dir(&home), &user);
    assert_eq!(
        lines,
        format!("{}\nexport PATH=\"$HOME/state/bin:$PATH\"\n", rc::MARK)
    );
    let written = rc::add(&home, &zshrc, &lines).unwrap().unwrap();
    assert!(
        rc::add(&home, &zshrc, &lines).unwrap().is_none(),
        "added twice"
    );
    let mut record = Record::load(&home).unwrap();
    record.rc = Some(written);
    record.save(&home).unwrap();
    assert_eq!(
        fs::read_to_string(&zshrc).unwrap(),
        format!("alias ll='ls -l'\n{lines}")
    );

    let (removed, rc) = remove(&home, &[Host::GeminiCli]).unwrap();
    assert_eq!(removed, [Removed::Deleted(shim_dir(&home).join("gemini"))]);
    assert_eq!(rc, None, "a shim is left, so the line stays");
    let (removed, rc) = remove(&home, &[Host::OpenCode]).unwrap();
    assert_eq!(removed.len(), 1);
    let backup = crate::install::backup_path(&zshrc, crate::install::HOOK_BACKUP);
    assert_eq!(
        rc,
        Some(rc::Undone::Restored(zshrc.clone(), backup.clone()))
    );
    assert_eq!(fs::read_to_string(&zshrc).unwrap(), "alias ll='ls -l'");
    assert!(!backup.exists());
    assert_eq!(Record::load(&home).unwrap(), Record::default());
}

#[test]
fn a_start_up_file_init_created_is_deleted_and_later_changes_are_kept() {
    let (_dir, home, user) = dirs();
    let lines = rc::lines(&shim_dir(&home), &user);
    let new = user.join(".zshrc");
    let written = rc::add(&home, &new, &lines).unwrap().unwrap();
    assert!(written.created);
    assert_eq!(
        rc::remove(&written).unwrap(),
        rc::Undone::Deleted(new.clone())
    );
    assert!(!new.exists());

    let kept = user.join(".bashrc");
    fs::write(&kept, "export A=1\n").unwrap();
    let written = rc::add(&home, &kept, &lines).unwrap().unwrap();
    let text = fs::read_to_string(&kept).unwrap();
    fs::write(&kept, format!("{text}export B=2\n")).unwrap();
    assert_eq!(
        rc::remove(&written).unwrap(),
        rc::Undone::Stripped(kept.clone())
    );
    assert_eq!(
        fs::read_to_string(&kept).unwrap(),
        "export A=1\nexport B=2\n"
    );
    assert_eq!(rc::remove(&written).unwrap(), rc::Undone::Absent(kept));
}

#[test]
fn the_start_up_file_is_the_shells_own_and_none_for_another_shell() {
    let user = Path::new("/u");
    assert_eq!(rc::file(user, Some("/bin/zsh")), Some(user.join(".zshrc")));
    let bash = if cfg!(target_os = "macos") {
        ".bash_profile"
    } else {
        ".bashrc"
    };
    assert_eq!(rc::file(user, Some("/usr/bin/bash")), Some(user.join(bash)));
    assert_eq!(rc::file(user, Some("/usr/bin/fish")), None);
    assert_eq!(rc::file(user, None), None);
    // A directory outside the home is written whole, safe in quotes.
    let lines = rc::lines(Path::new("/opt/a\"$b/bin"), user);
    assert!(
        lines.ends_with("export PATH=\"/opt/a\\\"\\$b/bin:$PATH\"\n"),
        "{lines}"
    );
}

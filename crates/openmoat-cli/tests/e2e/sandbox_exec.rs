//! The generated Codex profile, executed by Codex's own sandbox when a `codex`
//! binary is available (`MOAT_CODEX_BIN`, else `codex` on `PATH`). Without one
//! the test says so and passes; CI's `standard tier` job sets `MOAT_CODEX_BIN`
//! to a pinned binary on macOS and Linux and fails it if the binary is missing.
//!
//! `moat init` runs with that binary's directory first on `PATH`, as after a
//! user installs Codex: on Linux the profile then lets commands read Codex's
//! own executable, which Codex runs again inside bubblewrap (#371). Without
//! that, Codex on Linux starts no command at all (#421), including when the
//! standalone installer put Codex in the Codex home (#374).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::common::{Sandbox, output, skip_without_host_binary, text};

fn codex_binary() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("MOAT_CODEX_BIN").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(explicit));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join("codex"))
        .find(|p| p.is_file())
}

/// Run `cat <file>` in `project` under the `moat` profile; `Some(contents)` when it was readable.
fn cat(codex: &Path, sb: &Sandbox, project: &Path, file: &str) -> Option<String> {
    let out = cat_output(codex, sb, project, file);
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `moat init` with `dir` first on `PATH`, where the user installed Codex.
fn init(sb: &Sandbox, dir: &Path) {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let dirs = std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&path));
    let out = output(
        sb.command()
            .args(["init", "--yes"])
            .env("PATH", std::env::join_paths(dirs).unwrap()),
        None,
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

fn cat_output(codex: &Path, sb: &Sandbox, project: &Path, file: &str) -> Output {
    Command::new(codex)
        .args(["sandbox", "-P", "moat", "-C"])
        .arg(project)
        .args(["--", "/bin/cat", file])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &sb.home)
        .env("CODEX_HOME", sb.home.join(".codex"))
        .output()
        .expect("running codex sandbox")
}

#[test]
fn codex_enforces_the_generated_profile() {
    let Some(codex) = codex_binary() else {
        skip_without_host_binary("the generated Codex profile (set MOAT_CODEX_BIN)");
        return;
    };
    let sb = Sandbox::bare(&[".codex"]);
    init(&sb, codex.parent().unwrap());
    let project = sb.project();
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    fs::write(project.join(".env"), "TOKEN=fake").unwrap();
    fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    fs::write(sb.home.join(".ssh/id_rsa"), "FAKE-KEY").unwrap();

    let main = cat_output(&codex, &sb, &project, "main.rs");
    assert_eq!(
        String::from_utf8_lossy(&main.stdout),
        "fn main() {}",
        "the project stays readable: {}",
        text(&main)
    );
    assert_eq!(cat(&codex, &sb, &project, ".env"), None, "secrets-paths");
    let key = sb.home.join(".ssh/id_rsa");
    assert_eq!(
        cat(&codex, &sb, &project, &key.to_string_lossy()),
        None,
        "secrets-paths"
    );
    let system = cat(&codex, &sb, &project, "/etc/hosts");
    assert!(system.is_some(), "a read root stays readable");
}

/// Codex's standalone installer (`scripts/install/install.sh` in openai/codex)
/// keeps the executable in the Codex home, in
/// `packages/standalone/releases/<version>-<target>/bin/codex` behind a
/// `current` link, and links `~/.local/bin/codex` to it. Codex on Linux runs that
/// file again inside the sandbox, so the profile must let commands read it
/// while the rest of the Codex home stays hidden (#374).
#[cfg(unix)]
#[test]
fn codex_from_the_standalone_installer_starts_commands() {
    use std::os::unix::fs::symlink;

    let Some(codex) = codex_binary() else {
        skip_without_host_binary("the generated Codex profile (set MOAT_CODEX_BIN)");
        return;
    };
    // Outside the read roots (`/tmp`), as a home directory is.
    let sb = Sandbox::bare_in(Path::new(env!("CARGO_TARGET_TMPDIR")), &[".codex"]);
    let standalone = sb.home.join(".codex/packages/standalone");
    let install = |version: &str| {
        let release = standalone.join(format!("releases/{version}-x86_64-unknown-linux-musl"));
        fs::create_dir_all(release.join("bin")).unwrap();
        fs::copy(&codex, release.join("bin/codex")).unwrap();
        let current = standalone.join("current");
        if fs::symlink_metadata(&current).is_ok() {
            fs::remove_file(&current).unwrap();
        }
        symlink(&release, current).unwrap();
    };
    install("0.160.1");
    let bin = sb.home.join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    let installed = bin.join("codex");
    symlink(standalone.join("current/bin/codex"), &installed).unwrap();
    let state = ["auth.json", "state_5.sqlite"].map(|name| sb.home.join(".codex").join(name));
    for file in &state {
        fs::write(file, "FAKE-STATE").unwrap();
    }
    init(&sb, &bin);
    let project = sb.project();
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let starts = |when: &str| {
        let main = cat_output(&installed, &sb, &project, "main.rs");
        assert_eq!(
            String::from_utf8_lossy(&main.stdout),
            "fn main() {}",
            "commands start {when}: {}",
            text(&main)
        );
    };

    starts("after `moat init`");
    for file in &state {
        assert_eq!(
            cat(&installed, &sb, &project, &file.to_string_lossy()),
            None,
            "the Codex home stays hidden: {}",
            file.display()
        );
    }
    // Codex updates itself: a new release directory, `current` moved to it.
    install("0.161.0");
    starts("after an update, without `moat sandbox sync`");
}

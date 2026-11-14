//! The `plugins/` folder (ADR-099): generated from the host specs, so the
//! packages and the hooks `openmoat init` writes cannot drift apart; and what
//! a package does on its own, before any `openmoat` runs: it blocks the call
//! when there is none, passes the guard's answer on, adds `--plugin`, and
//! blocks when the guard gives no answer.
//!
//! Regenerate with `OPENMOAT_TEST_UPDATE_PLUGINS=1 cargo test -p openmoat-hosts --test plugins`.
//!
//! Unix only: the generated hook commands quote for the shell of the system
//! they are generated on, and the guard script is POSIX `sh`, so the folder
//! is the POSIX one and its scripts run here only.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use openmoat_hosts::plugin::{PROGRAM, files, spec};
use openmoat_hosts::{Host, NOT_INSTALLED, PLUGIN_FLAG, Plugin, PluginFile};

const UPDATE: &str = "OPENMOAT_TEST_UPDATE_PLUGINS";

fn folder() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins")
}

/// Every file under `dir`, relative to it with `/` separators.
fn on_disk(dir: &Path, base: &Path, out: &mut BTreeMap<String, PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            on_disk(&path, base, out);
        } else {
            let relative = path.strip_prefix(base).unwrap();
            let relative = relative.to_string_lossy().replace('\\', "/");
            out.insert(relative, path);
        }
    }
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    fs::metadata(path).unwrap().permissions().mode() & 0o111 != 0
}

fn write_all(wanted: &[PluginFile]) {
    let root = folder();
    let mut present = BTreeMap::new();
    on_disk(&root, &root, &mut present);
    for (relative, path) in &present {
        if !wanted.iter().any(|file| &file.path == relative) {
            fs::remove_file(path).unwrap();
        }
    }
    for file in wanted {
        let path = root.join(&file.path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &file.text).unwrap();
        #[cfg(unix)]
        set_executable(&path, file.executable);
    }
}

/// The generated hook commands quote for the shell of the system they are
/// generated on, and the guard script is POSIX `sh`: the folder is the POSIX
/// one, so Windows does not compare it.
#[cfg(not(windows))]
#[test]
fn the_plugins_folder_is_generated_from_the_specs() {
    let wanted = files();
    if std::env::var_os(UPDATE).is_some() {
        write_all(&wanted);
    }
    let root = folder();
    let mut present = BTreeMap::new();
    on_disk(&root, &root, &mut present);
    let mut wrong = Vec::new();
    for file in &wanted {
        match present.remove(&file.path) {
            None => wrong.push(format!("missing: {}", file.path)),
            Some(path) => {
                if fs::read_to_string(&path).unwrap() != file.text {
                    wrong.push(format!("differs: {}", file.path));
                }
                #[cfg(unix)]
                if is_executable(&path) != file.executable {
                    wrong.push(format!("executable bit: {}", file.path));
                }
            }
        }
    }
    wrong.extend(
        present
            .keys()
            .map(|stray| format!("not generated: {stray}")),
    );
    assert!(
        wrong.is_empty(),
        "plugins/ is stale; run `{UPDATE}=1 cargo test -p openmoat-hosts --test plugins`:\n  {}",
        wrong.join("\n  ")
    );
}

/// Every agent `openmoat init` sets up has a package or says why it has none.
#[test]
fn every_installable_host_has_a_package_or_a_reason() {
    for host in Host::ALL {
        match host.spec().plugin {
            Plugin::None { why } => assert!(!why.is_empty(), "{host:?} gives no reason"),
            Plugin::Package(spec) => {
                assert!(
                    !spec.install.is_empty() && !spec.publish.is_empty(),
                    "{host:?}"
                );
                for source in spec.sources {
                    assert!(source.starts_with("https://"), "{host:?}: {source}");
                }
                let files = (spec.files)(host, &openmoat_hosts::plugin::META);
                assert!(files.len() >= 2, "{host:?} has too few files: {files:?}");
                for file in &files {
                    // Nothing `init` fills in is left, and no package downloads.
                    assert!(!file.text.contains("= __MOAT_"), "{host:?}: {}", file.path);
                    assert!(!file.text.contains("curl "), "{host:?}: {}", file.path);
                }
            }
        }
    }
    let packaged = Host::ALL
        .iter()
        .filter(|host| spec(**host).is_some())
        .count();
    assert!(packaged >= 9, "{packaged}");
}

/// The JavaScript plugins `init` writes block with the same words when there
/// is no `openmoat`, and the packages run the one on the search path with
/// `--plugin`.
#[test]
fn the_javascript_plugins_say_the_one_install_command() {
    let literal = serde_json::Value::from(NOT_INSTALLED).to_string();
    let mut found = 0;
    for file in files() {
        let Some(ext) = Path::new(&file.path).extension() else {
            continue;
        };
        if ext != "js" && ext != "mjs" {
            continue;
        }
        found += 1;
        assert!(file.text.contains(&literal), "{}", file.path);
        let unusable = serde_json::Value::from(openmoat_hosts::LOCK_UNUSABLE).to_string();
        assert!(file.text.contains(&unusable), "{}", file.path);
        // The lock first, then the installers' folders the guard script uses.
        assert!(file.text.contains(r#"join(home, ".moat", "policy.lock")"#));
        assert_eq!(openmoat_hosts::LOCK_FILE, ".moat/policy.lock");
        for dir in openmoat_hosts::INSTALL_DIRS {
            let js = match dir.strip_prefix("$HOME/") {
                Some(rest) => {
                    let parts: Vec<String> = rest.split('/').map(|p| format!("\"{p}\"")).collect();
                    format!("join(home, {})", parts.join(", "))
                }
                None => format!("\"{dir}\""),
            };
            assert!(file.text.contains(&js), "{}: {js}", file.path);
        }
        assert!(
            file.text.contains(&format!(
                "const MOAT = {};",
                serde_json::Value::from(PROGRAM)
            )),
            "{}",
            file.path
        );
        assert!(
            file.text.contains("const MOAT_HOME = \"\";"),
            "{}",
            file.path
        );
        assert!(
            file.text.contains(&format!("[\"{PLUGIN_FLAG}\"]")),
            "{}",
            file.path
        );
    }
    assert_eq!(found, 3, "pi, OpenCode and OpenClaw");
}

/// A scratch folder in the system temp directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A new, empty scratch folder.
fn scratch() -> Scratch {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("openmoat-plugins-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// The guard script of each hook-command package, made to look only in
/// `dirs` after the search path.
fn scripts(dirs: &str) -> Vec<(Host, String)> {
    let mut out = Vec::new();
    for host in Host::ALL {
        let Some(spec) = spec(host) else { continue };
        for file in (spec.files)(host, &openmoat_hosts::plugin::META) {
            if !file.executable {
                continue;
            }
            let start = file.text.find("  for dir in ").unwrap();
            let end = start + file.text[start..].find("; do").unwrap();
            let mut text = file.text.clone();
            text.replace_range(start..end, &format!("  for dir in {dirs}"));
            out.push((host, text));
        }
    }
    out
}

/// Run `script` with `args`, `payload` on stdin, and only `path` as PATH.
#[cfg(unix)]
fn run(script: &str, args: &[&str], path: &Path, home: &Path) -> (i32, String, String) {
    use std::io::Write as _;
    let dir = scratch();
    let file = dir.path().join("openmoat-guard");
    fs::write(&file, script).unwrap();
    let mut child = Command::new("/bin/sh")
        .arg(&file)
        .args(args)
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A script that blocks before it runs `openmoat` exits without reading
    // the payload; the pipe closing then is its answer, not a failure.
    let written = child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"tool_name\":\"Bash\"}");
    if let Err(e) = written {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The deny each host reads for its default event, as the package prints it.
fn deny_doc(host: Host, why: &str) -> String {
    host.render_response(
        &openmoat_hosts::HookEvent::default(),
        &openmoat_core::Decision::single(openmoat_core::Verdict::Deny, "kernel-error", why),
    )
}

#[cfg(unix)]
#[test]
fn without_openmoat_every_hook_package_blocks_and_names_the_install_command() {
    let empty = scratch();
    let home = scratch();
    let scripts = scripts("\"$HOME/none\"");
    assert_eq!(
        scripts.len(),
        5,
        "Claude Code, Cursor, Gemini CLI, Copilot CLI, agy"
    );
    for (host, script) in scripts {
        let (code, stdout, stderr) = run(
            &script,
            &["guard", "--host", host.id()],
            empty.path(),
            home.path(),
        );
        assert_eq!(code, deny_exit(host), "{host:?}: {stdout} {stderr}");
        assert_eq!(stdout.trim_end(), deny_doc(host, NOT_INSTALLED), "{host:?}");
        assert!(stderr.contains(NOT_INSTALLED), "{host:?}: {stderr}");
    }
}

/// The exit code `host`'s guard script blocks with.
fn deny_exit(host: Host) -> i32 {
    spec(host).unwrap().deny_exit
}

/// A policy lock in `home` naming `binary`, as `openmoat init` writes it
/// (pretty JSON, `binary` at the top level).
#[cfg(unix)]
fn lock(home: &Path, binary: &str) {
    let path = home.join(openmoat_hosts::LOCK_FILE);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let doc =
        serde_json::json!({ "version": 1, "pinned_at_ms": 1, "binary": binary, "entries": {} });
    fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
}

/// With a lock, the script runs the binary it pins and nothing on the search
/// path or in the installers' folders, which the agent's environment or a
/// repository could fill; a lock naming no program it can run blocks.
#[cfg(unix)]
#[test]
fn a_hook_package_runs_the_binary_the_lock_pins() {
    for (host, _) in scripts("\"$HOME/none\"") {
        let pinned = scratch();
        let planted = scratch();
        let home = scratch();
        fake(pinned.path(), "{\"pinned\":1}", 0);
        fake(planted.path(), "{\"planted\":1}", 0);
        let found = scripts(&format!("{}", planted.path().display()))
            .into_iter()
            .find(|(h, _)| *h == host)
            .unwrap()
            .1;
        let binary = pinned.path().join(PROGRAM);
        lock(home.path(), &binary.to_string_lossy());
        let args = ["guard", "--host", host.id()];
        let (code, stdout, _) = run(&found, &args, planted.path(), home.path());
        assert_eq!((code, stdout.trim_end()), (0, "{\"pinned\":1}"), "{host:?}");

        // The pinned binary gone, a relative one, or one with an escape: blocked.
        for named in [
            pinned.path().join("gone").to_string_lossy().into_owned(),
            "openmoat".to_owned(),
            "/a\\\"b/openmoat".to_owned(),
        ] {
            lock(home.path(), &named);
            let (code, stdout, stderr) = run(&found, &args, planted.path(), home.path());
            assert_eq!(code, deny_exit(host), "{host:?} {named}: {stdout}");
            assert_eq!(
                stdout.trim_end(),
                deny_doc(host, openmoat_hosts::LOCK_UNUSABLE),
                "{host:?}"
            );
            assert!(stderr.contains(openmoat_hosts::LOCK_UNUSABLE), "{stderr}");
        }
    }
}

/// A stand-in `openmoat` in `dir` that records its arguments and answers
/// `answer` with `code`.
#[cfg(unix)]
fn fake(dir: &Path, answer: &str, code: i32) {
    use std::os::unix::fs::PermissionsExt as _;
    let file = dir.join(PROGRAM);
    let script = format!(
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$*\" > \"{}/args\"\nprintf '%s' '{answer}'\nexit {code}\n",
        dir.display()
    );
    fs::write(&file, script).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn a_hook_package_runs_openmoat_with_plugin_and_passes_its_answer_on() {
    let home = scratch();
    for (host, script) in scripts("\"$HOME/none\"") {
        let bin = scratch();
        // Found in a folder OpenMoat's installers use, off the search path.
        let found = scripts(&format!("{}", bin.path().display()))
            .into_iter()
            .find(|(h, _)| *h == host)
            .unwrap()
            .1;
        fake(bin.path(), "{\"decision\":\"x\"}", 0);
        let empty = scratch();
        let (code, stdout, _) = run(
            &found,
            &["guard", "--host", host.id()],
            empty.path(),
            home.path(),
        );
        assert_eq!(
            (code, stdout.trim_end()),
            (0, "{\"decision\":\"x\"}"),
            "{host:?}"
        );

        // On the search path: the arguments, then `--plugin`.
        let args = ["guard", "--host", host.id(), "--event", "preToolUse"];
        let (code, _, _) = run(&script, &args, bin.path(), home.path());
        assert_eq!(code, 0, "{host:?}");
        let seen = fs::read_to_string(bin.path().join("args")).unwrap();
        assert_eq!(
            seen.trim_end(),
            format!("{} {PLUGIN_FLAG}", args.join(" ")),
            "{host:?}"
        );

        // No decision passes on as no output.
        fake(bin.path(), "", 0);
        let (code, stdout, _) = run(&script, &args, bin.path(), home.path());
        assert_eq!((code, stdout.as_str()), (0, ""), "{host:?}");

        // A deny passes on, with the exit code the host blocks on.
        fake(bin.path(), "{\"d\":1}", 2);
        let (code, stdout, _) = run(&script, &args, bin.path(), home.path());
        assert_eq!(
            (code, stdout.trim_end()),
            (deny_exit(host), "{\"d\":1}"),
            "{host:?}"
        );

        // A crash, or exit 2 without an answer, blocks in the host's own form.
        for code in [1, 2, 64, 101] {
            fake(bin.path(), "", code);
            let (exit, stdout, stderr) = run(&script, &args, bin.path(), home.path());
            assert_eq!(exit, deny_exit(host), "{host:?} {code}: {stderr}");
            assert!(
                stdout.contains("deny") || stdout.contains("block"),
                "{host:?}: {stdout}"
            );
            assert!(
                stderr.contains(&format!("exited {code}")),
                "{host:?}: {stderr}"
            );
        }
    }
}

/// `python3` on the search path.
fn python() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| {
            dir.join(if cfg!(windows) {
                "python.exe"
            } else {
                "python3"
            })
        })
        .find(|path| path.is_file())
}

/// What Hermes Agent's callback in the package returns for a shell call, with
/// only `path` as PATH, as JSON (`null` for no directive).
fn hermes(python: &Path, path: &Path, home: &Path) -> serde_json::Value {
    let source = files()
        .into_iter()
        .find(|file| file.path.ends_with("/__init__.py"))
        .unwrap();
    let dir = scratch();
    let module = dir.path().join("plugin.py");
    fs::write(&module, &source.text).unwrap();
    let code = "import importlib.util, json, sys\n\
                spec = importlib.util.spec_from_file_location('openmoat_plugin', sys.argv[1])\n\
                m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n\
                hooks = []\n\
                m.register(type('C', (), {'register_hook': lambda s, e, f: hooks.append((e, f))})())\n\
                assert hooks[0][0] == 'pre_tool_call', hooks\n\
                print(json.dumps(hooks[0][1](tool_name='terminal', args={'command': 'ls'}, task_id='t')))\n";
    let out = Command::new(python)
        .arg("-I")
        .arg("-c")
        .arg(code)
        .arg(&module)
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}{stdout}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&stdout).unwrap()
}

#[cfg(unix)]
#[test]
fn the_hermes_package_blocks_without_openmoat_and_reads_the_guard() {
    let Some(python) = python() else {
        eprintln!("skipping the Hermes package test: `python3` is not on PATH");
        return;
    };
    // `$HOME/.cargo/bin` is one of the folders it looks in: an empty home.
    let home = scratch();
    let empty = scratch();
    let reply = hermes(&python, empty.path(), home.path());
    assert_eq!(reply["action"], "block", "{reply}");
    assert!(
        reply["message"].as_str().unwrap().contains(NOT_INSTALLED),
        "{reply}"
    );

    // The binary the lock pins runs, though no search path holds it.
    let bin = scratch();
    fake(
        bin.path(),
        "{\"decision\":\"block\",\"reason\":\"moat: deny [x]\"}",
        2,
    );
    lock(home.path(), &bin.path().join(PROGRAM).to_string_lossy());
    let reply = hermes(&python, empty.path(), home.path());
    assert_eq!(reply["message"], "moat: deny [x]", "{reply}");
    let seen = fs::read_to_string(bin.path().join("args")).unwrap();
    assert_eq!(
        seen.trim_end(),
        format!("guard --host hermes {PLUGIN_FLAG}")
    );

    fake(bin.path(), "", 0);
    assert_eq!(
        hermes(&python, empty.path(), home.path()),
        serde_json::Value::Null
    );
    fake(bin.path(), "", 1);
    assert_eq!(
        hermes(&python, empty.path(), home.path())["action"],
        "block"
    );

    // A lock naming no program it can run blocks.
    lock(home.path(), &bin.path().join("gone").to_string_lossy());
    let reply = hermes(&python, bin.path(), home.path());
    assert_eq!(reply["action"], "block", "{reply}");
    assert!(
        reply["message"]
            .as_str()
            .unwrap()
            .contains(openmoat_hosts::LOCK_UNUSABLE),
        "{reply}"
    );
}

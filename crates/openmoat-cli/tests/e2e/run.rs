//! `moat run` (Lightweight tier, ADR-018). On macOS and Linux the payloads
//! really run under the generated Seatbelt profile or Landlock rules; they are
//! `/bin/sh` scripts, never an agent, in an isolated home with fake secrets.

use std::path::{Path, PathBuf};
use std::process::Output;

use crate::common::{OK, Sandbox, USAGE, output, stderr, text};

/// `moat run -- /bin/sh -c <script>` in the project, with the temp directory
/// outside the home so that writing the home is not a temp-directory write.
fn run_sh(sb: &Sandbox, project: &Path, script: &str) -> Output {
    run_sh_with(sb, project, script, &[])
}

/// [`run_sh`] with `env` set for `moat run` itself.
fn run_sh_with(sb: &Sandbox, project: &Path, script: &str, env: &[(&str, &str)]) -> Output {
    let tmp = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    output(
        sb.command()
            .current_dir(project)
            .env("TMPDIR", &tmp)
            .envs(env.iter().copied())
            .args(["run", "--", "/bin/sh", "-c", script]),
        None,
    )
}

fn installed_with_secret() -> (Sandbox, PathBuf) {
    // Landlock cannot deny inside a granted tree, and `/tmp` is a read root, so
    // on Linux the home must live elsewhere for its secrets to be out of reach,
    // as a real home is.
    let parent = if cfg!(target_os = "linux") {
        PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
    } else {
        std::env::temp_dir()
    };
    let sb = Sandbox::bare_in(&parent, &[]);
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(OK), "moat init: {}", text(&out));
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::write(sb.home.join(".ssh/id_rsa"), "FAKE-SSH-KEY").unwrap();
    let project = sb.project();
    (sb, project)
}

#[test]
fn refuses_to_start_over_a_drifted_lock() {
    let (sb, project) = installed_with_secret();
    let policy = sb.home.join(".moat/policy.yaml");
    let edited = std::fs::read_to_string(&policy).unwrap() + "\n# edited\n";
    std::fs::write(&policy, edited).unwrap();
    let out = run_sh(&sb, &project, "echo ran");
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(stderr(&out).contains("drift"), "{}", text(&out));
    assert!(!text(&out).contains("ran\n"));
}

/// `moat run --isolate -- /bin/sh -c 'echo ran'` with `PATH` set to `path`.
#[cfg(target_os = "macos")]
fn run_isolated(path: &str) -> Output {
    let (sb, project) = installed_with_secret();
    output(
        sb.command().current_dir(&project).env("PATH", path).args([
            "run",
            "--isolate",
            "--",
            "/bin/sh",
            "-c",
            "echo ran",
        ]),
        None,
    )
}

/// The Isolated tier needs a virtual machine on macOS (#175): refused, never
/// the Lightweight tier instead.
#[cfg(target_os = "macos")]
#[test]
fn isolate_is_refused_on_macos() {
    let out = run_isolated("/usr/bin:/bin");
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(stderr(&out).contains("#175"), "{}", text(&out));
    assert!(!text(&out).contains("ran\n"), "{}", text(&out));
}

/// bubblewrap starts unconfined, so it comes from the system's directories,
/// never from `PATH`: a `bwrap` the project ships on a relative entry does
/// not run. Without a system one the agent does not start at all.
#[cfg(target_os = "linux")]
#[test]
fn isolate_never_runs_a_bwrap_from_path() {
    use std::os::unix::fs::PermissionsExt as _;

    let (sb, project) = installed_with_secret();
    let marker = project.join("project-bwrap-ran");
    let fake = project.join("bin/bwrap");
    std::fs::create_dir_all(project.join("bin")).unwrap();
    std::fs::write(&fake, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = output(
        sb.command()
            .current_dir(&project)
            .env("PATH", "bin:/usr/bin:/bin")
            .args(["run", "--isolate", "--", "/bin/sh", "-c", "echo ran"]),
        None,
    );
    assert!(!marker.exists(), "the project's bwrap ran: {}", text(&out));
    let system = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];
    if !system.iter().any(|p| Path::new(p).exists()) {
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(stderr(&out).contains("needs bubblewrap"), "{}", text(&out));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn refuses_where_no_sandbox_can_be_generated() {
    let (sb, project) = installed_with_secret();
    // An agent that exists everywhere: this binary, which would print its version.
    let agent = env!("CARGO_BIN_EXE_moat");
    let out = output(
        sb.command()
            .current_dir(&project)
            .args(["run", "--", agent, "--version"]),
        None,
    );
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    assert!(
        stderr(&out).contains("needs an operating-system sandbox"),
        "{}",
        text(&out)
    );
    assert!(
        out.stdout.is_empty(),
        "the agent did not run: {}",
        text(&out)
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod confined {
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::process::Command;

    use super::*;
    use crate::common::{FAILED, stdout};

    /// False, saying so, on a Linux kernel without Landlock ABI 4: `moat run`
    /// refuses there, which `refuses_*` cases cover. CI kernels have it, so
    /// there the tests must run.
    pub fn ran(out: &Output) -> bool {
        let unsupported = stderr(out).contains("needs Landlock ABI 4");
        assert!(
            !(unsupported && std::env::var_os("CI").is_some()),
            "CI's kernel must have Landlock ABI 4: {}",
            text(out)
        );
        if unsupported {
            eprintln!("skipped: this kernel has no Landlock ABI 4");
        }
        !unsupported
    }

    /// False, saying so, where `moat run --isolate` refused because bubblewrap
    /// is missing or cannot create its namespaces. CI's Linux job installs it,
    /// so there the tests must run.
    pub fn isolated(out: &Output) -> bool {
        let shown = stderr(out);
        let unavailable = shown.contains("needs bubblewrap") || shown.contains("bubblewrap cannot");
        assert!(
            !(unavailable && std::env::var_os("CI").is_some()),
            "CI must run the Isolated tier: {}",
            text(out)
        );
        if unavailable {
            eprintln!("skipped: bubblewrap cannot run here: {shown}");
        }
        !unavailable
    }

    /// `run` again, at most twice more, while curl could not even open a
    /// connection to the proxy. On some macos-14 runners Seatbelt refuses a
    /// connect that the profile's `localhost:<port>` rule allows: EPERM for a
    /// few milliseconds about every 15 s, in any sandbox with that rule, before
    /// the proxy sees anything (#280). A proxy that is really unreachable stays so.
    pub fn retried(mut run: impl FnMut() -> Output) -> Output {
        let mut out = run();
        for _ in 0..2 {
            if !refused_before_the_proxy(&out) {
                break;
            }
            eprintln!("retrying: the sandbox refused the connection to the proxy (#280)");
            out = run();
        }
        out
    }

    /// curl's message for a connection to the proxy port that never opened.
    fn refused_before_the_proxy(out: &Output) -> bool {
        let shown = text(out);
        let port = shown
            .split("proxy on 127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next());
        port.is_some_and(|p| shown.contains(&format!("Failed to connect to 127.0.0.1 port {p} ")))
    }

    #[test]
    fn only_a_refused_connection_to_the_proxy_is_retried() {
        use std::os::unix::process::ExitStatusExt as _;
        let notice = "moat run: /bin/sh in a sandbox\n  network: only through OpenMoat's \
                      proxy on 127.0.0.1:49205 (audit session proxy-1)\n";
        let output = |curl: &str| Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: format!("{notice}{curl}").into_bytes(),
        };
        // The failure CI saw (#280), and the expected refusal of a direct connection.
        let proxy = "curl: (7) Failed to connect to 127.0.0.1 port 49205 after 0 ms: \
                     Couldn't connect to server\n";
        let direct = "curl: (7) Failed to connect to 127.0.0.1 port 49206 after 0 ms: \
                      Couldn't connect to server\n";
        assert!(refused_before_the_proxy(&output(proxy)));
        assert!(!refused_before_the_proxy(&output(direct)));
        assert!(!refused_before_the_proxy(&output("")));
        let mut runs = 0;
        retried(|| {
            runs += 1;
            output(proxy)
        });
        assert_eq!(runs, 3, "two more tries, then the failure stands");
    }

    #[test]
    fn secrets_and_writes_outside_the_project_are_refused_and_work_goes_on() {
        let (sb, project) = installed_with_secret();
        let git_init = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .status();
        assert!(git_init.is_ok_and(|s| s.success()));
        let out = run_sh(
            &sb,
            &project,
            "cat \"$HOME/.ssh/id_rsa\"; echo \"read=$?\"
             echo x > \"$HOME/outside.txt\"; echo \"write=$?\"
             echo y > inside.txt; echo \"project=$?\"
             git status --short > /dev/null; echo \"git=$?\"",
        );
        if !ran(&out) {
            return;
        }
        let shown = text(&out);
        assert_eq!(out.status.code(), Some(OK), "{shown}");
        for expected in ["read=1", "project=0", "git=0"] {
            assert!(stdout(&out).contains(expected), "{expected}: {shown}");
        }
        // A failed redirection is 1 in bash (macOS `sh`) and 2 in dash (Debian `sh`).
        assert!(!stdout(&out).contains("write=0"), "{shown}");
        assert!(
            shown.contains("Operation not permitted") || shown.contains("Permission denied"),
            "EPERM or EACCES: {shown}"
        );
        assert!(!shown.contains("FAKE-SSH-KEY"), "{shown}");
        assert!(!sb.home.join("outside.txt").exists());
        assert!(project.join("inside.txt").exists());
        assert!(
            stderr(&out).contains("turn the agent's own sandbox off"),
            "{shown}"
        );
        assert!(
            stderr(&out).contains("wider; --verbose for details)"),
            "{shown}"
        );
        assert!(!stderr(&out).contains("stricter: "), "{shown}");
    }

    /// The proxy reads a brokered secret from `moat run`'s environment; the agent
    /// and its commands never see that variable, only the placeholder.
    #[test]
    fn an_env_brokered_secret_is_not_in_the_agents_environment() {
        let (sb, project) = installed_with_secret();
        let mut add = sb.command();
        add.args(["secret", "add", "gh"])
            .env("MOAT_ASSUME_TTY", "1");
        let added = output(&mut add, Some("y\n"));
        assert_eq!(added.status.code(), Some(OK), "{}", text(&added));
        // Generated for the test; no real token is used.
        let value = "fake-gh-token-3f9a1c";
        let out = run_sh_with(
            &sb,
            &project,
            "echo \"token=${GITHUB_TOKEN-unset}\"; env | grep -c fake-gh-token",
            &[("GITHUB_TOKEN", value)],
        );
        if !ran(&out) {
            return;
        }
        let shown = text(&out);
        assert!(stdout(&out).contains("token=unset"), "{shown}");
        assert!(!shown.contains(value), "{shown}");
    }

    #[test]
    fn network_goes_only_to_the_proxy_which_refuses_loopback() {
        let (sb, project) = installed_with_secret();
        let local = TcpListener::bind("127.0.0.1:0").unwrap();
        local.set_nonblocking(true).unwrap();
        let url = format!("http://127.0.0.1:{}/", local.local_addr().unwrap().port());
        // `-S` on the proxy request: its error is what `retried` looks for.
        let script = format!(
            "curl -s -m 5 --noproxy '*' {url}; echo \"direct=$?\"
             curl -sS -m 30 -o /dev/null -w 'proxy=%{{http_code}}\\n' {url}"
        );
        let out = retried(|| run_sh(&sb, &project, &script));
        if !ran(&out) {
            return;
        }
        let shown = text(&out);
        assert!(stdout(&out).contains("direct=7"), "{shown}");
        assert!(stdout(&out).contains("proxy=403"), "{shown}");
        assert_eq!(
            local.accept().map(drop).map_err(|e| e.kind()),
            Err(ErrorKind::WouldBlock),
            "nothing reached the local service"
        );
    }

    /// The proxy serves the run's session alone (ADR-027): the agent's proxy
    /// URL carries the credential, and a request without it, or with a wrong
    /// token, gets 407 before its host is decided.
    #[test]
    fn the_proxy_needs_the_runs_credential() {
        let (sb, project) = installed_with_secret();
        let script = r#"case "$HTTPS_PROXY" in
               "http://$MOAT_RUN_SESSION:"*@127.0.0.1:*) echo userinfo=yes ;;
             esac
             addr="${HTTPS_PROXY#*@}"
             curl -sS -m 30 -o /dev/null -w 'bare=%{http_code}\n' -x "http://$addr" http://127.0.0.1:9/
             curl -sS -m 30 -o /dev/null -w 'wrong=%{http_code}\n' \
               -x "http://$MOAT_RUN_SESSION:wrong-token@$addr" http://127.0.0.1:9/
             curl -sS -m 30 -o /dev/null -w 'session=%{http_code}\n' http://127.0.0.1:9/"#;
        let out = retried(|| run_sh(&sb, &project, script));
        if !ran(&out) {
            return;
        }
        let shown = text(&out);
        let printed = stdout(&out);
        assert!(printed.contains("userinfo=yes"), "{shown}");
        assert!(printed.contains("bare=407"), "{shown}");
        assert!(printed.contains("wrong=407"), "{shown}");
        // With the credential the request is decided: loopback is refused.
        assert!(printed.contains("session=403"), "{shown}");
    }

    /// Landlock alone leaves Unix sockets (the user's D-Bus session bus) and
    /// UDP open; the seccomp filter closes them, and `io_uring` around them.
    #[cfg(target_os = "linux")]
    #[test]
    fn unix_udp_and_io_uring_fail_with_eperm_and_tcp_to_the_proxy_works() {
        let (sb, project) = installed_with_secret();
        let out = run_sh(
            &sb,
            &project,
            r#"python3 -c '
import ctypes, socket
for name, family, kind in (("unix", socket.AF_UNIX, socket.SOCK_STREAM),
                           ("udp", socket.AF_INET, socket.SOCK_DGRAM)):
    try:
        socket.socket(family, kind).close()
        print(name + "=open")
    except OSError as e:
        print(name + "=" + str(e.errno))
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(425, 1, None)  # io_uring_setup
print("io_uring=" + str(ctypes.get_errno()))
'
             curl -s -m 30 -o /dev/null -w 'proxy=%{http_code}\n' http://127.0.0.1:9/"#,
        );
        if !ran(&out) {
            return;
        }
        let shown = text(&out);
        for expected in ["unix=1\n", "udp=1\n", "io_uring=1\n", "proxy=403"] {
            assert!(stdout(&out).contains(expected), "{expected}: {shown}");
        }
    }

    #[test]
    fn git_uses_a_planted_bare_repository_only_when_named() {
        let (sb, project) = installed_with_secret();
        let bare = Command::new("git")
            .args(["init", "-q", "--bare", "evil"])
            .current_dir(&project)
            .status();
        assert!(bare.is_ok_and(|s| s.success()));
        let tmp = sb.home.with_file_name("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let out = output(
            sb.command()
                .current_dir(&project)
                .env("TMPDIR", &tmp)
                .env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", "user.name")
                .env("GIT_CONFIG_VALUE_0", "kept")
                .args(["run", "--", "/bin/sh", "-c"])
                .arg(
                    "git config --get safe.bareRepository; git config --get user.name
                     cd evil && git rev-parse --git-dir > /dev/null; echo \"bare=$?\"
                     git --git-dir=. rev-parse --git-dir > /dev/null; echo \"named=$?\"",
                ),
            None,
        );
        if !ran(&out) {
            return;
        }
        let shown = text(&out);
        assert!(stdout(&out).starts_with("explicit\nkept\n"), "{shown}");
        assert!(stdout(&out).contains("named=0"), "{shown}");
        // CI's git knows the key (2.38 or later); macOS 12's 2.37 ignores it.
        if std::env::var_os("CI").is_some() {
            assert!(stdout(&out).contains("bare=128"), "{shown}");
            assert!(shown.contains("bare repository"), "{shown}");
        }
    }

    #[test]
    fn a_failing_agent_exits_1() {
        let (sb, project) = installed_with_secret();
        let out = run_sh(&sb, &project, "exit 2");
        if ran(&out) {
            assert_eq!(out.status.code(), Some(FAILED), "{}", text(&out));
        }
    }
}

//! Programs that run the command line they are given with something about the
//! process changed, read like the wrappers in `tables.rs`: the CPUs, scheduling
//! or memory it gets (`taskset`, `chrt`, `numactl`), its namespaces, limits,
//! user or sandbox (`unshare`, `nsenter`, `prlimit`, `setpriv`, `chpst`,
//! `cgexec`, `firejail`, `sandbox-exec`), a tracer or debugger (`strace`,
//! `ltrace`, `valgrind`, `catchsegv`, `gdb --args`), a faked clock or a proxy
//! (`faketime`, `torsocks`, `proxychains`), another architecture (`arch`), a
//! multi-call binary's applet (`busybox cp`, `toybox ln`), or outside this
//! session (`systemd-run`, `systemd-inhibit`, `daemonize`, `start-stop-daemon`,
//! `launchctl submit`).
//!
//! An option missing from these tables could take the word after it as its
//! value and hide the command, so every word that starts a shell or OpenMoat
//! itself is also classified as the start of a command line ([`runs`]): a
//! spurious one only adds the atoms of the command that word starts.

use crate::shell::tables::SHELLS;
use crate::shell::tokens::basename;

/// Each launcher, with its options that consume the next word.
const LAUNCHERS: &[(&str, &[&str])] = &[
    ("taskset", &[]),
    (
        "chrt",
        &[
            "-T",
            "--sched-runtime",
            "-P",
            "--sched-period",
            "-D",
            "--sched-deadline",
        ],
    ),
    (
        "unshare",
        &[
            "-S",
            "--setuid",
            "-G",
            "--setgid",
            "-R",
            "--root",
            "-w",
            "--wd",
            "--map-user",
            "--map-group",
            "--map-users",
            "--map-groups",
            "--propagation",
            "--setgroups",
            "--monotonic",
            "--boottime",
        ],
    ),
    (
        "nsenter",
        &["-t", "--target", "-S", "--setuid", "-G", "--setgid"],
    ),
    ("prlimit", &["-p", "--pid", "-o", "--output"]),
    (
        "numactl",
        &[
            "-N",
            "--cpunodebind",
            "-m",
            "--membind",
            "-C",
            "--physcpubind",
            "-p",
            "--preferred",
            "-i",
            "--interleave",
            "-P",
            "--preferred-many",
            "-w",
            "--weighted-interleave",
        ],
    ),
    ("cgexec", &["-g"]),
    ("firejail", &[]),
    (
        "systemd-run",
        &[
            "-u",
            "--unit",
            "-p",
            "--property",
            "--description",
            "--slice",
            "-H",
            "--host",
            "-M",
            "--machine",
            "-C",
            "--capsule",
            "--uid",
            "--gid",
            "--nice",
            "-E",
            "--setenv",
            "--working-directory",
            "--on-active",
            "--on-boot",
            "--on-startup",
            "--on-unit-active",
            "--on-unit-inactive",
            "--on-calendar",
            "--timer-property",
            "--path-property",
            "--socket-property",
            "--service-type",
            "--background",
        ],
    ),
    ("systemd-inhibit", &["--what", "--who", "--why", "--mode"]),
    (
        "strace",
        &[
            "-o", "-e", "-p", "-s", "-a", "-E", "-I", "-O", "-S", "-u", "-X", "-P", "-b",
        ],
    ),
    (
        "ltrace",
        &[
            "-o", "-e", "-p", "-s", "-a", "-n", "-u", "-l", "-x", "-F", "-A", "-D", "-w",
        ],
    ),
    ("valgrind", &[]),
    ("catchsegv", &[]),
    ("arch", &["-arch", "-d", "-e"]),
    ("sandbox-exec", &["-f", "-n", "-p", "-D"]),
    (
        "chpst",
        &[
            "-u", "-U", "-b", "-e", "-/", "-n", "-l", "-L", "-m", "-d", "-o", "-p", "-f", "-c",
            "-r", "-t",
        ],
    ),
    (
        "setpriv",
        &[
            "--reuid",
            "--regid",
            "--ruid",
            "--euid",
            "--rgid",
            "--egid",
            "--groups",
            "--securebits",
            "--pdeathsig",
            "--selinux-label",
            "--apparmor-profile",
            "--inh-caps",
            "--ambient-caps",
            "--bounding-set",
            "--landlock-access",
            "--landlock-rule",
        ],
    ),
    ("faketime", &["--date-prog"]),
    (
        "torsocks",
        &[
            "-u",
            "--user",
            "-p",
            "--pass",
            "-a",
            "--address",
            "-P",
            "--port",
        ],
    ),
    ("proxychains", &["-f"]),
    ("proxychains4", &["-f"]),
    ("daemonize", &["-c", "-e", "-o", "-p", "-l", "-u", "-E"]),
    ("busybox", &[]),
    ("toybox", &[]),
];

/// Launchers that take one positional value before the command
/// (`taskset MASK cmd`, `chrt PRIORITY cmd`, `faketime TIME cmd`).
const WITH_VALUE: &[&str] = &["taskset", "chrt", "faketime"];

/// `start-stop-daemon` options whose value is the program it starts.
const DAEMON_PROGRAMS: &[(&str, &str)] = &[("-x", "--exec"), ("-a", "--startas")];

/// `launchctl submit` options that consume the next word; `-p` names the
/// program it runs in place of the command's first word.
const SUBMIT_VALUES: &[&str] = &["-l", "-p", "-o", "-e"];

/// The options with a value of `program` when it is a launcher.
pub(super) fn options(program: &str) -> Option<&'static [&'static str]> {
    LAUNCHERS
        .iter()
        .find(|(name, _)| *name == program)
        .map(|(_, options)| *options)
}

/// True when `program` is one of the launchers of this module.
pub(super) fn is_launcher(program: &str) -> bool {
    options(program).is_some() || matches!(program, "gdb" | "start-stop-daemon" | "launchctl")
}

/// True when `program` takes one positional value before its command.
pub(super) fn takes_value(program: &str) -> bool {
    WITH_VALUE.contains(&program)
}

/// The command lines `argv` runs besides the one read like a wrapper's, which
/// starts at `wrapped` (its index in `argv`, when there is one).
pub(super) fn runs(argv: &[String], program: &str, wrapped: Option<usize>) -> Vec<Vec<String>> {
    let mut found = match program {
        "gdb" => gdb(argv).into_iter().collect(),
        "start-stop-daemon" => start_stop_daemon(argv),
        "launchctl" => submit(argv),
        _ => Vec::new(),
    };
    let launcher = options(program).is_some() || !found.is_empty();
    if launcher {
        for start in 1..argv.len() {
            if Some(start) != wrapped && starts_command(&argv[start]) {
                found.push(argv[start..].to_vec());
            }
        }
    }
    found
}

/// A word that starts a shell or OpenMoat (by either name).
fn starts_command(word: &str) -> bool {
    let name = basename(word);
    SHELLS.contains(&name) || matches!(name, "openmoat" | "moat")
}

/// `gdb [OPTION]… --args PROGRAM ARG…` runs `PROGRAM ARG…`.
fn gdb(argv: &[String]) -> Option<Vec<String>> {
    let at = argv.iter().position(|a| a == "--args" || a == "-args")?;
    let rest = argv.get(at + 1..)?;
    (!rest.is_empty()).then(|| rest.to_vec())
}

/// `start-stop-daemon --start --exec PROGRAM -- ARG…` runs `PROGRAM ARG…`, as
/// does `--startas PROGRAM`; each one named is a command line of its own.
fn start_stop_daemon(argv: &[String]) -> Vec<Vec<String>> {
    let end = argv.iter().position(|a| a == "--");
    let options = &argv[1..end.unwrap_or(argv.len())];
    let after_end = end.map_or(&[][..], |end| &argv[end + 1..]);
    let mut found = Vec::new();
    for (i, arg) in options.iter().enumerate() {
        for (short, long) in DAEMON_PROGRAMS {
            let value = if arg == short || arg == long {
                options.get(i + 1).cloned()
            } else {
                arg.strip_prefix(long)
                    .and_then(|rest| rest.strip_prefix('='))
                    .or_else(|| arg.strip_prefix(short).filter(|r| !r.is_empty()))
                    .map(str::to_owned)
            };
            if let Some(program) = value {
                found.push(
                    std::iter::once(program)
                        .chain(after_end.iter().cloned())
                        .collect(),
                );
            }
        }
    }
    found
}

/// `launchctl submit -l LABEL [-p PROGRAM] [-o FILE] [-e FILE] -- COMMAND…`
/// runs `COMMAND…`, and with `-p` the program it names under the command's
/// arguments.
fn submit(argv: &[String]) -> Vec<Vec<String>> {
    if argv.get(1).map(String::as_str) != Some("submit") {
        return Vec::new();
    }
    let mut program = None;
    let mut i = 2;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') {
            break;
        }
        if SUBMIT_VALUES.contains(&arg.as_str()) {
            if arg == "-p" {
                program = argv.get(i + 1).cloned();
            }
            i += 1;
        }
        i += 1;
    }
    let command = argv.get(i..).unwrap_or_default();
    if command.is_empty() {
        return Vec::new();
    }
    let mut found = vec![command.to_vec()];
    if let Some(program) = program {
        found.push(
            std::iter::once(program)
                .chain(command[1..].iter().cloned())
                .collect(),
        );
    }
    found
}

#[cfg(test)]
mod tests {
    use super::runs;

    fn of(line: &str, wrapped: Option<usize>) -> Vec<String> {
        let argv: Vec<String> = line.split(' ').map(str::to_owned).collect();
        runs(&argv, &argv[0], wrapped)
            .iter()
            .map(|run| run.join(" "))
            .collect()
    }

    #[test]
    fn finds_the_command_each_special_launcher_runs() {
        assert_eq!(of("gdb -q --args ./a x", None), ["./a x"]);
        assert_eq!(of("gdb ./a", None), Vec::<String>::new());
        assert_eq!(
            of("start-stop-daemon --start -b --exec /bin/x -- a b", None),
            ["/bin/x a b"]
        );
        assert_eq!(
            of("start-stop-daemon -S -x /bin/x --startas=/bin/y", None),
            ["/bin/x", "/bin/y"]
        );
        assert_eq!(
            of("launchctl submit -l x -p /bin/y -- a b", None),
            ["a b", "/bin/y b"]
        );
        assert_eq!(of("launchctl submit -l x a", None), ["a"]);
        assert_eq!(of("launchctl list", None), Vec::<String>::new());
    }

    #[test]
    fn a_shell_or_openmoat_after_an_unknown_option_is_a_command() {
        assert_eq!(of("taskset --x 1 sh -c y", None), ["sh -c y"]);
        assert_eq!(of("taskset 1 sh -c y", Some(2)), Vec::<String>::new());
        assert_eq!(
            of("prlimit --frob v /usr/local/bin/openmoat allow", None),
            ["/usr/local/bin/openmoat allow"]
        );
        assert_eq!(
            of("taskset -c 0 cargo build", Some(3)),
            Vec::<String>::new()
        );
        // only launchers: a plain program's arguments are its own
        assert_eq!(of("cargo run -- sh", None), Vec::<String>::new());
    }
}

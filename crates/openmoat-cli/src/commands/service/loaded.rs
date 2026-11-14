//! What the service manager loaded for a job, as it reports it (ADR-094):
//! the installed file reading back right is not enough when the manager runs
//! something else under the same name. A systemd drop-in (beside the unit, or
//! in the runtime `user.control/` and `transient/` folders) changes
//! `ExecStart` without touching the unit; a plist bootstrapped from another
//! path under the same label passes every check of the installed file. So
//! `listen --service` also asks the manager where it loaded the job from and
//! what it runs, and refuses anything but the installed file, alone, running
//! the installed program.
//!
//! Pure parsers of `systemctl --user show` and `launchctl print`; the
//! platform files run the commands.

use std::path::Path;

/// Why `systemctl --user show <unit> -p FragmentPath -p DropInPaths -p
/// NeedDaemonReload -p ExecStart` (`show`) is not the unit at `unit` alone,
/// loaded as it is now, running `program`; empty when it is.
#[cfg(any(target_os = "linux", test))]
pub fn systemd(show: &str, unit: &Path, program: &[String]) -> Vec<String> {
    let value = |key: &str| {
        show.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(str::trim)
    };
    let mut findings = Vec::new();
    match value("FragmentPath") {
        Some(path) if Path::new(path) == unit => {}
        Some(path) => findings.push(format!(
            "systemd loaded it from {}, not {}",
            crate::render::clean(path),
            unit.display()
        )),
        None => findings.push("systemd does not say where it loaded it from".to_owned()),
    }
    match value("DropInPaths") {
        Some("") => {}
        Some(paths) => findings.push(format!(
            "systemd also applies {}, which can change what it runs",
            crate::render::clean(paths)
        )),
        None => findings.push("systemd does not say which drop-ins it applies".to_owned()),
    }
    if value("NeedDaemonReload") != Some("no") {
        findings.push("systemd has not loaded the unit as it is now".to_owned());
    }
    // `ExecStart={ path=… ; argv[]=a b c ; ignore_errors=no ; … }`: one
    // `argv[]` per command, on one line or several, so a second command is a
    // finding too.
    let commands: Vec<&str> = show
        .lines()
        .filter(|line| line.starts_with("ExecStart="))
        .flat_map(|line| line.split("argv[]=").skip(1))
        .map(|argv| argv.split(" ;").next().unwrap_or(argv).trim())
        .collect();
    if commands != [program.join(" ")] {
        findings.push(format!(
            "systemd runs {}, not {}",
            crate::render::clean(&commands.join(" and ")),
            program.join(" ")
        ));
    }
    findings
}

/// Why `launchctl print gui/<uid>/<label>` (`print`) is not the plist at
/// `plist` running `program`; empty when it is. Only the job's own keys,
/// one tab deep, count: nested blocks (environment, endpoints) are skipped.
#[cfg(any(target_os = "macos", test))]
pub fn launchd(print: &str, plist: &Path, program: &[String]) -> Vec<String> {
    let mut depth = 0usize;
    let mut path = None;
    let mut arguments: Option<Vec<String>> = None;
    let mut in_arguments = false;
    for line in print.lines() {
        let text = line.trim();
        if in_arguments {
            if text == "}" {
                in_arguments = false;
                depth -= 1;
            } else if let Some(arguments) = &mut arguments {
                arguments.push(text.to_owned());
            }
            continue;
        }
        if text.ends_with('{') {
            if depth == 1 && text == "arguments = {" {
                in_arguments = true;
                arguments = Some(Vec::new());
            }
            depth += 1;
            continue;
        }
        if text == "}" {
            depth = depth.saturating_sub(1);
            continue;
        }
        if depth == 1
            && path.is_none()
            && let Some(value) = text.strip_prefix("path = ")
        {
            path = Some(value.to_owned());
        }
    }
    let mut findings = Vec::new();
    match &path {
        Some(found) if Path::new(found) == plist => {}
        Some(found) => findings.push(format!(
            "launchd loaded it from {}, not {}",
            crate::render::clean(found),
            plist.display()
        )),
        None => findings.push("launchd does not say where it loaded it from".to_owned()),
    }
    match arguments {
        Some(found) if found == program => {}
        Some(found) => findings.push(format!(
            "launchd runs {}, not {}",
            crate::render::clean(&found.join(" ")),
            program.join(" ")
        )),
        None => findings.push("launchd does not say what it runs".to_owned()),
    }
    findings
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{launchd, systemd};

    fn program() -> Vec<String> {
        [
            "/usr/local/bin/openmoat",
            "approvals",
            "listen",
            "--service",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    const UNIT: &str = "/home/u/.config/systemd/user/openmoat-approvals.service";
    const EXEC: &str = "ExecStart={ path=/usr/local/bin/openmoat ; argv[]=/usr/local/bin/openmoat \
                        approvals listen --service ; ignore_errors=no ; start_time=[n/a] }";

    fn show(fragment: &str, drop_ins: &str, exec: &str) -> String {
        format!("FragmentPath={fragment}\nDropInPaths={drop_ins}\nNeedDaemonReload=no\n{exec}\n")
    }

    #[test]
    fn the_installed_unit_alone_passes() {
        assert_eq!(
            systemd(&show(UNIT, "", EXEC), Path::new(UNIT), &program()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_drop_in_another_unit_or_another_command_is_refused() {
        let drop_in = "/run/user/1000/systemd/user.control/openmoat-approvals.service.d/50-x.conf";
        let found = systemd(&show(UNIT, drop_in, EXEC), Path::new(UNIT), &program());
        assert!(found[0].contains("also applies"), "{found:?}");
        let found = systemd(
            &show(
                "/run/user/1000/systemd/transient/openmoat-approvals.service",
                "",
                EXEC,
            ),
            Path::new(UNIT),
            &program(),
        );
        assert!(found[0].contains("loaded it from"), "{found:?}");
        let other = EXEC.replace("--service", "--service ; argv[]=/tmp/x");
        let twice = format!("{EXEC}\nExecStart={{ path=/tmp/x ; argv[]=/tmp/x ; }}");
        for exec in [other, twice] {
            let found = systemd(&show(UNIT, "", &exec), Path::new(UNIT), &program());
            assert!(
                found.iter().any(|f| f.contains("runs")),
                "{exec}: {found:?}"
            );
        }
        let stale = show(UNIT, "", EXEC).replace("NeedDaemonReload=no", "NeedDaemonReload=yes");
        assert_eq!(systemd(&stale, Path::new(UNIT), &program()).len(), 1);
        // Nothing reported is refused, not passed.
        assert_eq!(systemd("", Path::new(UNIT), &program()).len(), 4);
    }

    const PLIST: &str = "/Users/u/Library/LaunchAgents/dev.openmoat.approvals.plist";

    fn print(path: &str, arguments: &[&str]) -> String {
        let arguments = arguments.iter().fold(String::new(), |mut out, a| {
            out.push_str("\t\t");
            out.push_str(a);
            out.push('\n');
            out
        });
        format!(
            "gui/501/dev.openmoat.approvals = {{\n\tactive count = 1\n\tpath = {path}\n\
             \ttype = LaunchAgent\n\tenvironment = {{\n\t\tpath = /elsewhere\n\t}}\n\
             \tprogram = /usr/local/bin/openmoat\n\targuments = {{\n{arguments}\t}}\n}}\n"
        )
    }

    #[test]
    fn the_installed_plist_passes_and_another_is_refused() {
        let args = [
            "/usr/local/bin/openmoat",
            "approvals",
            "listen",
            "--service",
        ];
        assert_eq!(
            launchd(&print(PLIST, &args), Path::new(PLIST), &program()),
            Vec::<String>::new()
        );
        let found = launchd(&print("/tmp/x.plist", &args), Path::new(PLIST), &program());
        assert!(
            found[0].contains("loaded it from /tmp/x.plist"),
            "{found:?}"
        );
        let found = launchd(
            &print(PLIST, &["/tmp/evil", "approvals", "listen", "--service"]),
            Path::new(PLIST),
            &program(),
        );
        assert!(found[0].contains("launchd runs /tmp/evil"), "{found:?}");
        assert_eq!(launchd("", Path::new(PLIST), &program()).len(), 2);
    }
}

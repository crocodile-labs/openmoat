//! `moat run` keeps commands from writing an agent's own configuration in the
//! project (hooks, MCP servers, extensions), which the agent loads in its next
//! session outside the sandbox, and from moving another agent's directory away.
//! CI files and commit-hook managers' files stay writable: installs write them.

use super::confined::ran;
use super::{installed_with_secret, run_sh};
use crate::common::{stdout, text};

/// On macOS Seatbelt denies them after every grant, wherever they are in the
/// project, existing or not, and in either case; `.claude`, `.codex` and the
/// like cannot be moved away or replaced by a directory moved into their
/// place, nor can the project's `.github` and `.pi`, which hold agent hooks.
#[cfg(target_os = "macos")]
#[test]
fn agent_configuration_and_directories_cannot_be_written_or_moved() {
    use crate::common::OK;

    let (sb, project) = installed_with_secret();
    // The directories exist: what is denied is the configuration inside.
    for dir in [".codex", ".claude", "sub/.cursor", "planted", ".github"] {
        std::fs::create_dir_all(project.join(dir)).unwrap();
    }
    let out = run_sh(
        &sb,
        &project,
        "echo '{}' > .mcp.json; echo \"mcp=$?\"
         echo '{}' > .MCP.json; echo \"case=$?\"
         mkdir -p .claude/hooks; echo \"hooks=$?\"
         echo '{}' > sub/.cursor/mcp.json; echo \"cursor=$?\"
         mv .codex codex-old; echo \"move=$?\"
         mv planted .gemini; echo \"replace=$?\"
         mv .github github-old; echo \"github=$?\"
         mkdir .pi; echo \"pi=$?\"
         mkdir -p .husky && echo 'npm test' > .husky/pre-commit; echo \"husky=$?\"
         mkdir -p .github/workflows && echo 'on: push' > .github/workflows/ci.yml; echo \"ci=$?\"",
    );
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    for denied in [
        "mcp", "case", "hooks", "cursor", "move", "replace", "github", "pi",
    ] {
        assert!(
            !stdout(&out).contains(&format!("{denied}=0\n")),
            "{denied}: {shown}"
        );
    }
    for allowed in ["husky=0\n", "ci=0\n"] {
        assert!(stdout(&out).contains(allowed), "{allowed}: {shown}");
    }
    assert!(!project.join(".mcp.json").exists(), "{shown}");
    assert!(!project.join(".claude/hooks").exists(), "{shown}");
    assert!(!project.join("sub/.cursor/mcp.json").exists(), "{shown}");
    assert!(project.join(".codex").is_dir(), "{shown}");
    assert!(!project.join(".gemini").exists(), "{shown}");
    assert!(project.join(".github").is_dir(), "{shown}");
    assert!(!project.join(".pi").exists(), "{shown}");
    assert!(project.join(".husky/pre-commit").exists(), "{shown}");
}

/// On Linux, where the agent gets a network namespace, an agent configuration
/// file and an agent's hook settings that exist directly in the project are
/// bound read-only, and the folders holding them cannot be renamed away.
#[cfg(target_os = "linux")]
#[test]
fn existing_agent_configuration_is_read_only_in_the_network_namespace() {
    use crate::common::stderr;

    let (sb, project) = installed_with_secret();
    std::fs::write(project.join(".mcp.json"), "{}").unwrap();
    for dir in [".github/hooks", ".claude"] {
        std::fs::create_dir_all(project.join(dir)).unwrap();
    }
    std::fs::write(project.join(".claude/settings.json"), "{}").unwrap();
    let out = run_sh(
        &sb,
        &project,
        "echo '{\"mcpServers\":{}}' > .mcp.json; echo \"mcp=$?\"
         rm -f .mcp.json; echo \"remove=$?\"
         echo '{\"hooks\":{}}' > .claude/settings.json; echo \"settings=$?\"
         mv .github github-old; echo \"github=$?\"
         mv .claude claude-old; echo \"claude=$?\"
         mkdir -p .husky && echo 'npm test' > .husky/pre-commit; echo \"husky=$?\"",
    );
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    let port_only = stderr(&out).contains("restricted by port only");
    super::check_netns(port_only, &shown);
    if port_only {
        eprintln!("skipped: bubblewrap cannot make a network namespace here");
        return;
    }
    for denied in ["mcp", "remove", "settings", "github", "claude"] {
        assert!(
            !stdout(&out).contains(&format!("{denied}=0\n")),
            "{denied}: {shown}"
        );
    }
    assert!(stdout(&out).contains("husky=0\n"), "{shown}");
    assert_eq!(
        std::fs::read_to_string(project.join(".mcp.json")).unwrap(),
        "{}"
    );
    assert_eq!(
        std::fs::read_to_string(project.join(".claude/settings.json")).unwrap(),
        "{}"
    );
    assert!(project.join(".github/hooks").is_dir(), "{shown}");
}

/// On Linux, with `~/.claude` a link to another folder, `--write ~/.claude`
/// grants the folder it points to; Claude Code's `settings.json` there stays
/// read-only to commands in the network namespace, and without one the run
/// refuses, as for an unlinked folder. Compared as text, the deny lay below
/// no grant and the file was writable.
#[cfg(target_os = "linux")]
#[test]
fn a_linked_agent_folder_keeps_its_hook_settings_out_of_reach() {
    use crate::common::{USAGE, output, stderr};

    let (sb, project) = installed_with_secret();
    let real = sb.home.join("real-claude");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(real.join("settings.json"), "{}").unwrap();
    std::os::unix::fs::symlink(&real, sb.home.join(".claude")).unwrap();
    let tmp = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let out = output(
        sb.command()
            .current_dir(&project)
            .env("TMPDIR", &tmp)
            .arg("run")
            .arg("--write")
            .arg(sb.home.join(".claude"))
            .args(["--", "/bin/sh", "-c"])
            .arg("echo x >> \"$HOME/.claude/settings.json\"; echo \"w=$?\""),
        None,
    );
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    if stderr(&out).contains("Install bubblewrap") {
        // no namespace: refused before anything starts
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must run in a namespace: {shown}"
        );
        assert_eq!(out.status.code(), Some(USAGE), "{shown}");
    } else {
        assert!(stdout(&out).contains("w="), "{shown}");
        assert!(!stdout(&out).contains("w=0\n"), "{shown}");
    }
    assert_eq!(
        std::fs::read_to_string(real.join("settings.json")).unwrap(),
        "{}",
        "{shown}"
    );
}

/// On Linux, an agent's hook settings that the project lacks when the agent
/// starts cannot be created by a command: in the network namespace and under
/// `--isolate` each is a read-only `{}` for the session, removed afterwards.
/// Created, `.gemini/settings.json` or `.claude/settings.local.json` with
/// `disableAllHooks` would run the next session without OpenMoat's hook.
#[cfg(target_os = "linux")]
#[test]
fn missing_hook_settings_cannot_be_created() {
    use super::confined::isolated;
    use crate::common::{output, stderr};

    const SCRIPT: &str = "mkdir -p .gemini && echo '{\"hooks\":{}}' > .gemini/settings.json; echo \"gemini=$?\"
         mkdir -p .github/copilot && echo '{}' > .github/copilot/settings.local.json; echo \"copilot=$?\"
         mkdir -p .claude && echo '{\"disableAllHooks\":true}' > .claude/settings.local.json; echo \"claude=$?\"
         mkdir -p .codex && echo '{}' > .codex/hooks.json; echo \"codex=$?\"
         cat .gemini/settings.json; echo
         mv .gemini gemini-old; echo \"move=$?\"";
    let created = [
        ".gemini/settings.json",
        ".github/copilot/settings.local.json",
        ".claude/settings.local.json",
        ".codex/hooks.json",
    ];
    for isolate in [false, true] {
        let (sb, project) = installed_with_secret();
        let tmp = sb.home.with_file_name("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let mut command = sb.command();
        command.current_dir(&project).env("TMPDIR", &tmp).arg("run");
        if isolate {
            command.arg("--isolate");
        }
        let out = output(command.args(["--", "/bin/sh", "-c", SCRIPT]), None);
        if !ran(&out) || (isolate && !isolated(&out)) {
            continue;
        }
        let shown = text(&out);
        let port_only = !isolate && stderr(&out).contains("restricted by port only");
        assert!(
            !(port_only && std::env::var_os("CI").is_some()),
            "CI must run `openmoat run` in a network namespace: {shown}"
        );
        if port_only {
            // Nothing covers them; the run names each when the agent exits.
            assert!(
                stderr(&out).contains(".gemini/settings.json did not exist"),
                "{shown}"
            );
            continue;
        }
        for denied in ["gemini", "copilot", "claude", "codex", "move"] {
            assert!(
                !stdout(&out).contains(&format!("{denied}=0\n")),
                "{denied} (isolate {isolate}): {shown}"
            );
        }
        // the agent reads the placeholder as settings that change nothing
        assert!(stdout(&out).contains("{}\n"), "{shown}");
        for file in created {
            assert!(
                !project.join(file).exists(),
                "{file} removed after the run (isolate {isolate}): {shown}"
            );
        }
        for folder in [".gemini", ".github", ".claude", ".codex"] {
            assert!(!project.join(folder).exists(), "{folder}: {shown}");
        }
    }
}

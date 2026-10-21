use std::fs;
use std::path::Path;

use openmoat_hosts::Host;

use super::*;
use crate::home::Home;
use crate::install::{HookFormat, HookSpec, backup_path, hook_file};

const SPECS: &[HookSpec] = &[HookSpec::new("tool_call", "", 45, false)];

fn config(dir: &Path) -> HostConfig {
    HostConfig {
        host: Host::Pi,
        settings_path: dir.join("extensions/openmoat.js"),
        dir: dir.to_path_buf(),
        hooks: SPECS,
        format: HookFormat::Pi,
        blocks_on_failure: || false,
    }
}

fn install(config: &HostConfig, binary: &Path) -> Outcome {
    let home = Home::at(config.dir().join("state"));
    hook_file::install(&home, config, binary, false).unwrap()
}

#[test]
fn the_extension_names_the_binary_once_and_waits_as_the_spec_says() {
    let text = text(Path::new(r#"/opt/my "tools"/openmoat"#)).unwrap();
    assert!(text.contains(r#"const MOAT = "/opt/my \"tools\"/openmoat";"#));
    assert!(!text.contains(BINARY_LINE));
    assert!(is_ours(&text));
    // The extension's own wait for `openmoat guard` is the hook timeout the
    // spec states, which outlasts the guard's budget.
    let installed = Host::Pi.spec().install.as_ref().unwrap();
    assert_eq!(installed.config_file, "extensions/openmoat.js");
    let timeout = installed.hooks[0].timeout;
    assert!(crate::install::GUARD_BUDGET_S < timeout);
    let wait = format!("const GUARD_TIMEOUT_MS = {timeout}_000;");
    assert!(SOURCE.contains(&wait), "{wait}");
    assert!(SOURCE.contains(r#"spawn(MOAT, ["guard", "--host", "pi"]"#));
}

#[test]
fn init_writes_the_extension_once_and_rewrites_it_for_another_binary() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let binary = Path::new("/usr/local/bin/openmoat");
    assert_eq!(hook_file::state(&cfg, binary), HookState::Missing);
    let home = Home::at(dir.path().join("state"));
    assert_eq!(
        hook_file::install(&home, &cfg, binary, true).unwrap(),
        Outcome::Installed
    );
    assert!(!cfg.settings_path.exists(), "a dry run writes nothing");
    assert_eq!(install(&cfg, binary), Outcome::Installed);
    assert_eq!(install(&cfg, binary), Outcome::Unchanged);
    assert_eq!(hook_file::state(&cfg, binary), HookState::Installed);
    assert_eq!(
        fs::read_to_string(&cfg.settings_path).unwrap(),
        text(binary).unwrap()
    );

    let other = Path::new("/opt/openmoat/bin/openmoat");
    assert_eq!(
        hook_file::state(&cfg, other),
        HookState::Stale {
            command: "/usr/local/bin/openmoat".to_owned()
        }
    );
    assert_eq!(install(&cfg, other), Outcome::Updated);
    assert_eq!(hook_file::state(&cfg, other), HookState::Installed);
    assert!(!backup_path(&cfg.settings_path, HOOK_BACKUP).exists());
}

#[test]
fn an_edited_extension_is_stale_and_a_file_of_the_persons_is_backed_up() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let binary = Path::new("/usr/local/bin/openmoat");
    install(&cfg, binary);
    let edited = text(binary)
        .unwrap()
        .replace("return await answer(", "return undefined; await answer(");
    fs::write(&cfg.settings_path, &edited).unwrap();
    assert!(matches!(
        hook_file::state(&cfg, binary),
        HookState::Stale { .. }
    ));
    assert_eq!(
        render(binary, &edited).unwrap(),
        Some(text(binary).unwrap())
    );
    assert_eq!(render(binary, &text(binary).unwrap()).unwrap(), None);

    let mine = "export default function (pi) {}\n";
    fs::write(&cfg.settings_path, mine).unwrap();
    assert_eq!(hook_file::state(&cfg, binary), HookState::Missing);
    assert_eq!(install(&cfg, binary), Outcome::Installed);
    let backup = backup_path(&cfg.settings_path, HOOK_BACKUP);
    assert_eq!(fs::read_to_string(backup).unwrap(), mine);
}

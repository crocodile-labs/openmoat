use std::fs;

use openmoat_hosts::{HookLayout, Host};

use super::*;
use crate::home::Home;

/// A `config.yaml` as Hermes Agent writes it, with a comment of the person's.
const ORIGINAL: &str = "model:\n  default: hermes-4  # the main model\nhooks:\n  post_tool_call:\n  - command: log.sh\n";

fn config(dir: &Path) -> HostConfig {
    let host = Host::ALL
        .into_iter()
        .find(|h| {
            h.spec()
                .install
                .as_ref()
                .is_some_and(|i| i.hook_file.is_yaml())
        })
        .unwrap();
    let install = host.spec().install.as_ref().unwrap();
    HostConfig {
        host,
        settings_path: dir.join(install.config_file),
        dir: dir.to_path_buf(),
        hooks: install.hooks,
        layout: install.hook_file,
        blocks_on_failure: || false,
    }
}

fn layout(config: &HostConfig) -> &'static dyn HookFile {
    match config.layout {
        HookLayout::Yaml(layout) => layout,
        other => panic!("{other:?}"),
    }
}

/// Approve the hook in the consent file, as `init` does.
fn approve(config: &HostConfig, binary: &Path) {
    let (path, text) = consent::planned(config, binary).unwrap().unwrap();
    fs::write(path, text).unwrap();
}

#[test]
fn the_entry_is_added_as_text_and_counts_once_it_is_approved() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path());
    let binary = Path::new("/x/openmoat");
    fs::write(&config.settings_path, ORIGINAL).unwrap();
    assert_eq!(state(&config, layout(&config), binary), HookState::Missing);
    let text = render(&config, layout(&config), binary, ORIGINAL)
        .unwrap()
        .unwrap();
    assert!(text.contains("# the main model"), "{text}");
    assert!(
        text.contains("  post_tool_call:\n  - command: log.sh\n"),
        "{text}"
    );
    fs::write(&config.settings_path, &text).unwrap();
    assert!(matches!(
        state(&config, layout(&config), binary),
        HookState::Unapproved(why) if why.contains("shell-hooks-allowlist.json")
    ));
    approve(&config, binary);
    assert_eq!(
        state(&config, layout(&config), binary),
        HookState::Installed
    );
    assert_eq!(
        render(&config, layout(&config), binary, &text).unwrap(),
        None,
        "nothing left to do"
    );
    assert!(consent::planned(&config, binary).unwrap().is_none());
    // Another binary is stale, in the hook file and in the consent file.
    let other = Path::new("/y/openmoat");
    assert!(matches!(
        state(&config, layout(&config), other),
        HookState::Stale { .. }
    ));
    assert!(consent::planned(&config, other).unwrap().is_some());
    assert_eq!(
        remove(&config, layout(&config), &text).unwrap().as_deref(),
        Some(ORIGINAL)
    );
}

#[test]
fn a_broken_file_is_unreadable_and_a_broken_allowlist_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path());
    let binary = Path::new("/x/openmoat");
    fs::write(&config.settings_path, "a: [\n").unwrap();
    assert!(matches!(
        state(&config, layout(&config), binary),
        HookState::Unreadable(_)
    ));
    let (path, _) = consent::of(&config).unwrap();
    fs::write(&path, "{\"approvals\": {}}").unwrap();
    let error = consent::planned(&config, binary).unwrap_err();
    assert!(format!("{error:#}").contains("not a list"), "{error:#}");
}

#[test]
fn install_approves_first_backs_up_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path());
    let home = Home::at(dir.path().join("state"));
    let binary = Path::new("/x/openmoat");
    fs::write(&config.settings_path, ORIGINAL).unwrap();
    assert_eq!(
        install(&home, &config, layout(&config), binary, false).unwrap(),
        Outcome::Installed
    );
    assert_eq!(
        state(&config, layout(&config), binary),
        HookState::Installed
    );
    let backup = super::super::backup_path(&config.settings_path, HOOK_BACKUP);
    assert_eq!(fs::read_to_string(backup).unwrap(), ORIGINAL);
    assert_eq!(
        install(&home, &config, layout(&config), binary, false).unwrap(),
        Outcome::Unchanged
    );
    // An allowlist that lost the entry is written again, the hook file left alone.
    let (path, _) = consent::of(&config).unwrap();
    fs::write(&path, "{\"approvals\": []}").unwrap();
    let before = fs::read(&config.settings_path).unwrap();
    assert_eq!(
        install(&home, &config, layout(&config), binary, false).unwrap(),
        Outcome::Updated
    );
    assert_eq!(fs::read(&config.settings_path).unwrap(), before);
    assert_eq!(
        state(&config, layout(&config), binary),
        HookState::Installed
    );
}

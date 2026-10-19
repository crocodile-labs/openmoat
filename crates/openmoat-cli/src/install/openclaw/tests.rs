use std::fs;
use std::path::Path;

use openmoat_hosts::Host;
use serde_json::{Value, json};

use super::*;
use crate::home::Home;
use crate::install::{HookFormat, HookSpec, hook_file};

const SPECS: &[HookSpec] = &[HookSpec {
    event: "before_tool_call",
    matcher: "",
    timeout: 60,
    block_on_failure: false,
}];

fn config(dir: &Path) -> HostConfig {
    HostConfig {
        host: Host::OpenClaw,
        settings_path: dir.join("openclaw.json"),
        dir: dir.to_path_buf(),
        hooks: SPECS,
        format: HookFormat::OpenClaw,
        blocks_on_failure: || false,
    }
}

fn install(config: &HostConfig, binary: &Path) -> Outcome {
    let home = Home::at(config.dir().join("state"));
    hook_file::install(&home, config, binary, false).unwrap()
}

fn root(config: &HostConfig) -> Value {
    serde_json::from_str(&fs::read_to_string(&config.settings_path).unwrap()).unwrap()
}

#[test]
fn the_plugin_source_names_the_binary_once_and_waits_less_than_openclaw() {
    const _: () = assert!(crate::install::GUARD_BUDGET_S < 45);
    const _: () = assert!(45 < crate::install::OPENCLAW_HOOK_TIMEOUT_S);
    let text = plugin_text(Path::new(r#"/opt/my "tools"/moat"#)).unwrap();
    assert!(text.contains(r#"const MOAT = "/opt/my \"tools\"/moat";"#));
    assert!(!text.contains(BINARY_LINE));
    // The plugin gives up on `moat guard` before OpenClaw gives up on the plugin.
    assert!(SOURCE.contains("const GUARD_TIMEOUT_MS = 45_000;"));
}

#[test]
fn init_writes_the_plugin_and_its_entries_once() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    fs::write(
        &cfg.settings_path,
        r#"{"agents":{"defaults":{"workspace":"~/w"}},"plugins":{"allow":["memory"],"deny":["openmoat"]}}"#,
    )
    .unwrap();
    let binary = Path::new("/usr/local/bin/moat");
    assert_eq!(install(&cfg, binary), Outcome::Installed);
    assert_eq!(install(&cfg, binary), Outcome::Unchanged);
    assert_eq!(hook_file::state(&cfg, binary), HookState::Installed);
    let doc = root(&cfg);
    let ours = crate::context::path_string(&plugin_path(&cfg));
    assert_eq!(doc["plugins"]["load"]["paths"], json!([ours]));
    assert_eq!(
        doc["plugins"]["entries"]["openmoat"],
        json!({"enabled": true, "hooks": {"timeouts": {"before_tool_call": 60000}}})
    );
    assert_eq!(doc["plugins"]["allow"], json!(["memory", "openmoat"]));
    assert_eq!(doc["plugins"]["deny"], json!([]));
    assert_eq!(doc["agents"]["defaults"]["workspace"], "~/w");
    let plugin = fs::read_to_string(plugin_path(&cfg)).unwrap();
    assert!(plugin.contains(r#"const MOAT = "/usr/local/bin/moat";"#));

    // Another binary, or a changed plugin file, is out of date until `init`.
    let other = Path::new("/opt/moat");
    assert!(matches!(
        hook_file::state(&cfg, other),
        HookState::Stale { .. }
    ));
    fs::write(plugin_path(&cfg), "export default {};").unwrap();
    assert!(matches!(
        hook_file::state(&cfg, binary),
        HookState::Stale { .. }
    ));
    assert_eq!(install(&cfg, binary), Outcome::Updated);
    assert_eq!(hook_file::state(&cfg, binary), HookState::Installed);
}

#[test]
fn remove_gives_back_the_file_init_found() {
    for original in [
        json!({}),
        json!({"gateway": {"port": 18789}, "plugins": {"allow": ["memory"], "load": {"paths": ["/x/p.ts"]}, "entries": {"memory": {"enabled": true}}}}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        fs::write(&cfg.settings_path, original.to_string()).unwrap();
        install(&cfg, Path::new("/x/moat"));
        let mut doc = root(&cfg);
        assert!(hook_file::remove(&mut doc, &cfg));
        assert_eq!(doc, original);
        assert!(!hook_file::remove(&mut doc, &cfg), "nothing left to remove");
        assert_eq!(remove_plugin(&cfg).unwrap(), Some(plugin_path(&cfg)));
        assert!(!plugin_path(&cfg).parent().unwrap().exists());
    }
}

#[test]
fn a_file_openmoat_cannot_load_its_plugin_from_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    fs::write(&cfg.settings_path, r#"{"plugins":{"enabled":false}}"#).unwrap();
    let home = Home::at(dir.path().join("state"));
    let refused = hook_file::install(&home, &cfg, Path::new("/x/moat"), false).unwrap_err();
    assert!(
        format!("{refused:#}").contains("plugins.enabled"),
        "{refused:#}"
    );
    // Writing a file with comments back as JSON would drop them: refused,
    // in the preview as well, and nothing is written.
    let commented = "{ // mine\n  gateway: { port: 18789 },\n}";
    fs::write(&cfg.settings_path, commented).unwrap();
    let refused = hook_file::install(&home, &cfg, Path::new("/x/moat"), false).unwrap_err();
    assert!(format!("{refused:#}").contains("comments"), "{refused:#}");
    let preview = hook_file::render(&cfg, Path::new("/x/moat"), commented).unwrap_err();
    assert!(format!("{preview:#}").contains("comments"), "{preview:#}");
    assert!(!plugin_path(&cfg).exists(), "nothing written");
    assert_eq!(fs::read_to_string(&cfg.settings_path).unwrap(), commented);
}

#[test]
fn json5_without_comments_is_read_and_written_back_as_json() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    fs::write(
        &cfg.settings_path,
        "{\n  gateway: { port: 18789, },\n  plugins: { allow: ['memory'] },\n}\n",
    )
    .unwrap();
    let binary = Path::new("/x/moat");
    assert_eq!(install(&cfg, binary), Outcome::Installed);
    let doc = root(&cfg);
    assert_eq!(doc["gateway"]["port"], 18789);
    assert_eq!(doc["plugins"]["allow"], json!(["memory", "openmoat"]));
    assert_eq!(hook_file::state(&cfg, binary), HookState::Installed);
    // Comments added after `init` change nothing to read: still installed,
    // and nothing to write.
    let text = fs::read_to_string(&cfg.settings_path).unwrap();
    fs::write(&cfg.settings_path, format!("// kept\n{text}")).unwrap();
    assert_eq!(hook_file::state(&cfg, binary), HookState::Installed);
    assert_eq!(install(&cfg, binary), Outcome::Unchanged);
}

#[test]
fn a_configuration_outside_the_state_directory_keeps_the_plugin_in_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = HostConfig {
        settings_path: dir.path().join("etc/main.json5"),
        ..config(&dir.path().join("state"))
    };
    fs::create_dir_all(dir.path().join("etc")).unwrap();
    fs::create_dir_all(dir.path().join("state")).unwrap();
    assert_eq!(install(&cfg, Path::new("/x/moat")), Outcome::Installed);
    assert_eq!(
        plugin_path(&cfg),
        dir.path().join("state/openmoat/openmoat.mjs")
    );
    assert!(plugin_path(&cfg).is_file());
    let ours = crate::context::path_string(&plugin_path(&cfg));
    assert_eq!(root(&cfg)["plugins"]["load"]["paths"], json!([ours]));
}

use std::fs;
use std::path::Path;

use openmoat_hosts::{HookFile, Host};
use serde_json::json;

use super::{Collect, digest_path, inside, plugin_hooks};

/// The first host whose spec names installed plugins, with its layout.
fn plugin_host() -> (Host, &'static dyn HookFile) {
    Host::ALL
        .into_iter()
        .find_map(|host| {
            let install = host.spec().install.as_ref()?;
            (!host.spec().ledger.plugin_hooks.is_empty())
                .then_some((host, install.hook_file.entries()?))
        })
        .unwrap()
}

fn write(path: &Path, value: &serde_json::Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, value.to_string()).unwrap();
}

/// A plugin's `hooks/hooks.json`, the hooks file its manifest names and the
/// event map it holds inline are all read; a path that climbs out is not.
#[test]
fn every_hook_a_plugin_brings_is_found() {
    let (host, layout) = plugin_host();
    let plugins = &host.spec().ledger.plugin_hooks[0];
    let dir = tempfile::tempdir().unwrap();
    let mut plugin = dir.path().to_path_buf();
    for part in plugins.dirs {
        plugin = plugin.join(if *part == openmoat_hosts::Activity::ANY {
            "x"
        } else {
            part
        });
    }
    let entry = |command: &str| json!([{"hooks": [{"type": "command", "command": command}]}]);
    let file = plugins
        .file
        .iter()
        .fold(plugin.clone(), |p, part| p.join(part));
    write(
        &file,
        &json!({"hooks": {"SessionStart": entry("./start.sh")}}),
    );
    write(
        &plugin.join("extra.json"),
        &json!({"hooks": {"Stop": entry("./stop.sh")}}),
    );
    write(
        &dir.path().join("outside.json"),
        &json!({"hooks": {"Stop": entry("./out.sh")}}),
    );
    let (manifest, key) = plugins.manifest.unwrap();
    let manifest = manifest.iter().fold(plugin.clone(), |p, part| p.join(part));
    let mut named = serde_json::Map::new();
    named.insert(
        key.to_owned(),
        json!(["./extra.json", "../../../../../outside.json", {"PreToolUse": entry("./pre.sh")}]),
    );
    write(&manifest, &serde_json::Value::Object(named));
    let mut scan = Collect::default();
    plugin_hooks(&mut scan, host, layout, dir.path(), plugins);
    let mut commands: Vec<String> = scan
        .found
        .values()
        .flat_map(|f| f.commands.clone())
        .collect();
    commands.sort();
    assert_eq!(commands, ["./pre.sh", "./start.sh", "./stop.sh"]);
}

#[test]
fn a_path_that_climbs_out_of_a_plugin_is_refused() {
    let root = Path::new("/p");
    assert_eq!(
        inside(root, "./hooks/x.json"),
        Some(root.join("hooks/x.json"))
    );
    assert_eq!(inside(root, "../x.json"), None);
    assert_eq!(inside(root, "/etc/x.json"), None);
    assert_eq!(inside(root, ""), None);
}

/// A directory is pinned by every file in it, so a changed file changes it.
#[test]
fn a_directory_digest_follows_its_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a"), "1").unwrap();
    let before = digest_path(dir.path()).unwrap();
    fs::write(dir.path().join("a"), "2").unwrap();
    assert_ne!(digest_path(dir.path()).unwrap(), before);
    assert_eq!(digest_path(&dir.path().join("missing")), None);
}

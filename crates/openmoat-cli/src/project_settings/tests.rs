use super::*;

fn warnings(cwd: &Path, user_home: &Path) -> Vec<String> {
    super::warnings(
        cwd,
        user_home,
        Host::ClaudeCode,
        &user_home.join(".claude/settings.json"),
    )
}

/// pi's extension, as `moat init` installs it under `user_home`.
fn pi_extension(user_home: &Path) -> PathBuf {
    user_home.join(".pi/agent/extensions/openmoat.js")
}

/// A trusted Gemini CLI folder's settings that turn hooks off or add one, and
/// a pi project's settings that turn OpenMoat's extension off and its own
/// extensions, are named with the agent that loads them.
#[test]
fn gemini_and_pi_project_settings_and_extensions_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join(".gemini")).unwrap();
    fs::create_dir_all(project.join(".pi/extensions/helper")).unwrap();
    let gemini = || {
        let ours = user_home.join(".gemini/settings.json");
        super::warnings(&project, &user_home, Host::GeminiCli, &ours)
    };
    let pi = || super::warnings(&project, &user_home, Host::Pi, &pi_extension(&user_home));
    fs::write(
        project.join(".gemini/settings.json"),
        r#"{"ui": {"theme": "x"}}"#,
    )
    .unwrap();
    fs::write(project.join(".pi/settings.json"), r#"{"theme": "dark"}"#).unwrap();
    fs::write(project.join(".pi/extensions/notes.md"), "not code").unwrap();
    assert!(gemini().is_empty());
    assert!(pi().is_empty());

    fs::write(
        project.join(".gemini/settings.json"),
        r#"{"hooksConfig": {"disabled": ["openmoat"]}, "hooks": {"BeforeTool": [{}]}}"#,
    )
    .unwrap();
    let rows = gemini();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].contains("`hooksConfig.disabled`"), "{rows:?}");
    assert!(rows[0].contains("`hooks`"), "{rows:?}");
    assert!(rows[0].contains("A Gemini CLI session"), "{rows:?}");

    fs::write(
        project.join(".pi/settings.json"),
        r#"{"extensions": ["!openmoat.js"]}"#,
    )
    .unwrap();
    fs::write(
        project.join(".pi/extensions/evil.ts"),
        "export default () => {}",
    )
    .unwrap();
    fs::write(project.join(".pi/extensions/helper/index.js"), "").unwrap();
    let rows = pi();
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(
        rows[0].contains("`!openmoat.js` turns OpenMoat's extension off"),
        "{rows:?}"
    );
    assert!(
        rows[1].contains("evil.ts: is an extension pi loads"),
        "{rows:?}"
    );
    assert!(rows[2].contains("helper: is an extension"), "{rows:?}");
}

/// The person's own settings file turns the hook off in each host's own way.
#[test]
fn a_user_settings_file_that_turns_the_hook_off_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("cfg");
    fs::create_dir_all(&cfg).unwrap();
    let hook = cfg.join("extensions/openmoat.js");
    let off = |host: Host, text: &str| {
        fs::write(cfg.join("settings.json"), text).unwrap();
        switched_off(host, &cfg, &hook)
    };
    for (host, text) in [
        (Host::ClaudeCode, r#"{"disableAllHooks": true}"#),
        (Host::CopilotCli, r#"{"disableAllHooks": true}"#),
        (Host::GeminiCli, r#"{"hooksConfig": {"enabled": false}}"#),
        (Host::Pi, r#"{"extensions": ["-extensions/openmoat.js"]}"#),
        (Host::Pi, "{ not json"),
    ] {
        let found = off(host, text).unwrap_or_else(|| panic!("{host}: {text}"));
        assert!(
            found.starts_with(&cfg.join("settings.json").display().to_string()),
            "{found}"
        );
    }
    for (host, text) in [
        // A project's own concerns are not the person's: hooks and env are theirs.
        (
            Host::ClaudeCode,
            r#"{"hooks": {"Stop": []}, "env": {"A": "b"}, "disableAllHooks": false}"#,
        ),
        (Host::CopilotCli, r#"{"model": "gpt-5"}"#),
        (
            Host::GeminiCli,
            r#"{"hooksConfig": {"disabled": ["lint"]}}"#,
        ),
        (Host::Pi, r#"{"extensions": ["-extensions/other.js"]}"#),
        // Hosts without such a file.
        (Host::Codex, r#"{"disableAllHooks": true}"#),
        (Host::Cursor, r#"{"disableAllHooks": true}"#),
    ] {
        assert_eq!(off(host, text), None, "{host}: {text}");
    }
    fs::remove_file(cfg.join("settings.json")).unwrap();
    assert_eq!(switched_off(Host::Pi, &cfg, &hook), None, "no file");
    // Codex reads `config.toml`, where OpenMoat's own profile sits too.
    let codex = cfg.join("config.toml");
    fs::write(
        &codex,
        "default_permissions = \"moat\"\n[features]\nhooks = false\n",
    )
    .unwrap();
    let found = switched_off(Host::Codex, &cfg, &cfg.join("hooks.json")).unwrap();
    assert!(found.contains("`features.hooks`"), "{found}");
    fs::write(
        &codex,
        "default_permissions = \"moat\"\n[features]\nnetwork_proxy = true\n",
    )
    .unwrap();
    assert_eq!(
        switched_off(Host::Codex, &cfg, &cfg.join("hooks.json")),
        None
    );
}

/// A trusted Codex project's `.codex/` layer and a Cursor project's
/// `.cursor/hooks.json` add hooks beside OpenMoat's.
#[test]
fn codex_and_cursor_project_hooks_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join(".codex")).unwrap();
    fs::create_dir_all(project.join(".cursor")).unwrap();
    let rows = |host: Host| super::warnings(&project, &user_home, host, Path::new("/x"));
    fs::write(project.join(".codex/config.toml"), "model = \"gpt-5\"\n").unwrap();
    fs::write(
        project.join(".cursor/hooks.json"),
        r#"{"version": 1, "hooks": {}}"#,
    )
    .unwrap();
    assert!(rows(Host::Codex).is_empty());
    assert!(rows(Host::Cursor).is_empty());
    fs::write(
        project.join(".codex/config.toml"),
        "[features]\nhooks = false\n",
    )
    .unwrap();
    fs::write(
        project.join(".codex/hooks.json"),
        r#"{"hooks": {"PreToolUse": [{}]}}"#,
    )
    .unwrap();
    let hooks = r#"{"version": 1, "hooks": {"beforeShellExecution": [{"command": "./x"}]}}"#;
    fs::write(project.join(".cursor/hooks.json"), hooks).unwrap();
    let codex = rows(Host::Codex);
    assert_eq!(codex.len(), 2, "{codex:?}");
    assert!(codex[0].contains("`features.hooks`"), "{codex:?}");
    assert!(
        codex[1].contains("hooks.json: `hooks` adds hooks"),
        "{codex:?}"
    );
    let cursor = rows(Host::Cursor);
    assert_eq!(cursor.len(), 1, "{cursor:?}");
    assert!(cursor[0].contains("A Cursor session"), "{cursor:?}");
    fs::write(project.join(".codex/config.toml"), "[features\n").unwrap();
    assert!(rows(Host::Codex)[0].contains("cannot be checked"));
}

/// A repository's Copilot settings that turn hooks off, and each hook file in
/// its `.github/hooks`, are named with the agent that loads them.
#[test]
fn copilot_repository_settings_and_hook_files_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join(".github/copilot")).unwrap();
    fs::create_dir_all(project.join(".github/hooks")).unwrap();
    let ours = user_home.join(".copilot/hooks/openmoat.json");
    let copilot = || super::warnings(&project, &user_home, Host::CopilotCli, &ours);
    assert!(copilot().is_empty());
    fs::write(
        project.join(".github/copilot/settings.json"),
        r#"{"model": "gpt-5"}"#,
    )
    .unwrap();
    fs::write(project.join(".github/hooks/notes.txt"), "not a hook").unwrap();
    assert!(
        copilot().is_empty(),
        "a model choice and other files are left alone"
    );
    fs::write(
        project.join(".github/copilot/settings.local.json"),
        r#"{"disableAllHooks": true}"#,
    )
    .unwrap();
    fs::write(project.join(".github/hooks/audit.json"), "{}").unwrap();
    let rows = copilot();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0].contains("`disableAllHooks`"), "{rows:?}");
    assert!(rows[1].contains("audit.json: adds hooks"), "{rows:?}");
    assert!(
        rows.iter()
            .all(|r| r.contains("A GitHub Copilot CLI session")),
        "{rows:?}"
    );
    assert!(
        warnings(&project, &user_home).is_empty(),
        "not Claude Code's"
    );
}

/// A file that passes the check but is rewritten before the decision is
/// reported, whatever it holds by then; one left as it was passes.
#[test]
fn a_file_rewritten_during_the_check_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    fs::write(&path, r#"{"model": "opus"}"#).unwrap();
    assert_eq!(check_unchanged(&path), None);
    let swapped = check_between(&path, || {
        fs::write(&path, r#"{"disableAllHooks": true}"#).unwrap();
    });
    assert!(swapped.unwrap().contains("changed while"));
    fs::write(&path, "{}").unwrap();
    let touched = check_between(&path, || fs::write(&path, "{ }").unwrap());
    assert!(
        touched.unwrap().contains("changed while"),
        "bytes, not meaning"
    );
    let gone = dir.path().join("gone.json");
    let created = check_between(&gone, || fs::write(&gone, "{}").unwrap());
    assert!(created.unwrap().contains("changed while"), "appeared");
    fs::remove_file(&gone).unwrap();
    assert_eq!(check_unchanged(&gone), None);
    fs::write(&path, r#"{"hooks": {"Stop": [{}]}}"#).unwrap();
    assert!(
        check_between(&path, || panic!("not read again"))
            .unwrap()
            .contains("`hooks`")
    );
}

#[test]
fn reading_tells_absent_from_broken() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read_bytes(&dir.path().join("none.json")).unwrap().is_none());
    assert_eq!(check(&dir.path().join("none.json")), None);
    let path = dir.path().join("settings.json");
    fs::write(&path, "// comment\n{}").unwrap();
    assert!(check(&path).unwrap().starts_with("cannot be checked"));
    fs::write(&path, " ".repeat(usize::try_from(MAX_BYTES).unwrap() + 1)).unwrap();
    assert!(check(&path).unwrap().contains("larger than"));
    fs::write(&path, r#"{"env": {"HTTPS_PROXY": "http://x"}}"#).unwrap();
    assert!(check(&path).unwrap().contains("`env`"));
}

#[test]
fn warns_for_the_session_directory_and_its_project_root_not_the_home() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    let sub = project.join("sub");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join(".claude")).unwrap();
    fs::create_dir_all(sub.join(".claude")).unwrap();
    fs::create_dir_all(user_home.join(".claude")).unwrap();
    fs::write(
        user_home.join(".claude/settings.json"),
        r#"{"hooks": {"Stop": [{}]}}"#,
    )
    .unwrap();
    assert!(warnings(&sub, &user_home).is_empty());
    assert!(warnings(&user_home, &user_home).is_empty(), "user settings");

    fs::write(
        project.join(".claude/settings.json"),
        r#"{"disableAllHooks": true}"#,
    )
    .unwrap();
    fs::write(sub.join(".claude/settings.local.json"), "{").unwrap();
    let rows = warnings(&sub, &user_home);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter().any(|r| r.contains("`disableAllHooks`")),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("cannot be checked")),
        "{rows:?}"
    );
    assert!(rows[0].contains("review the file"), "{rows:?}");
}

/// An OpenCode project's `opencode.json`, read with its comments as OpenCode
/// reads it, and its `.opencode/plugins/` are named; a `plugin` list that only
/// adds turns nothing off, so the person's own file with one names nothing.
#[test]
fn opencode_project_configuration_and_plugins_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join(".opencode/plugins")).unwrap();
    let plugin = user_home.join(".config/opencode/plugins/openmoat.js");
    let opencode = || super::warnings(&project, &user_home, Host::OpenCode, &plugin);
    fs::write(
        project.join("opencode.json"),
        "{\n  // the model\n  \"model\": \"x/y\",\n}\n",
    )
    .unwrap();
    assert!(opencode().is_empty(), "{:?}", opencode());

    fs::write(
        project.join("opencode.json"),
        "{\n  // added\n  \"plugin\": [\"opencode-helper\"],\n  \"mcp\": {\"db\": {\"type\": \"local\", \"command\": [\"db\"]}},\n}\n",
    )
    .unwrap();
    fs::write(
        project.join(".opencode/plugins/helper.ts"),
        "export default async () => ({})",
    )
    .unwrap();
    let rows = opencode();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0].contains("`plugin` loads plugins"), "{rows:?}");
    assert!(rows[0].contains("`mcp` adds MCP servers"), "{rows:?}");
    assert!(
        rows[1].contains("helper.ts: is a plugin OpenCode loads"),
        "{rows:?}"
    );

    let config = user_home.join(".config/opencode");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("opencode.json"), "{\"plugin\": [\"x\"]}").unwrap();
    assert_eq!(switched_off(Host::OpenCode, &config, &plugin), None);
}

/// OpenCode reads `opencode.jsonc` and `.opencode/opencode.jsonc` as it reads
/// the `.json` files, and loads `.opencode/plugin/` as it loads `plugins/`.
#[test]
fn opencode_jsonc_files_and_the_singular_plugin_folder_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let project = user_home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::create_dir_all(project.join(".opencode/plugin")).unwrap();
    let plugin = user_home.join(".config/opencode/plugins/openmoat.js");
    let loads = "{\n  // added\n  \"plugin\": [\"opencode-helper\"],\n}\n";
    fs::write(project.join("opencode.jsonc"), loads).unwrap();
    fs::write(project.join(".opencode/opencode.jsonc"), loads).unwrap();
    fs::write(
        project.join(".opencode/plugin/helper.js"),
        "export default async () => ({})",
    )
    .unwrap();
    // Compared with `/` whatever the platform writes between the names.
    let rows: Vec<String> = super::warnings(&project, &user_home, Host::OpenCode, &plugin)
        .iter()
        .map(|row| row.replace('\\', "/"))
        .collect();
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(
        rows[0].contains("opencode.jsonc: `plugin` loads plugins"),
        "{rows:?}"
    );
    assert!(
        rows[1].contains(".opencode/opencode.jsonc: `plugin`"),
        "{rows:?}"
    );
    assert!(
        rows[2].contains("plugin/helper.js: is a plugin OpenCode loads"),
        "{rows:?}"
    );
}

/// OpenCode 2 removes OpenMoat's plugin for `-openmoat` in `plugins`: in the
/// person's `opencode.json` or `opencode.jsonc` OpenCode is not protected, in a
/// project's the warning says its sessions are not.
#[test]
fn a_removal_of_openmoats_opencode_plugin_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let user_home = dir.path().join("home");
    let config = user_home.join(".config/opencode");
    let plugin = config.join("plugins/openmoat.js");
    fs::create_dir_all(&config).unwrap();
    let removes = "{\n  // drops it\n  \"plugins\": [\"-openmoat\"],\n}\n";
    for name in ["opencode.json", "opencode.jsonc"] {
        fs::write(config.join(name), removes).unwrap();
        let found = switched_off(Host::OpenCode, &config, &plugin).unwrap();
        assert!(found.contains(name) && found.contains("`-openmoat`"), "{found}");
        fs::remove_file(config.join(name)).unwrap();
    }
    assert_eq!(switched_off(Host::OpenCode, &config, &plugin), None);

    let project = user_home.join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::write(project.join("opencode.json"), removes).unwrap();
    let rows = super::warnings(&project, &user_home, Host::OpenCode, &plugin);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].contains("does not protect OpenCode 2 sessions started here"),
        "{rows:?}"
    );
}

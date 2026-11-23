//! The places that still name a host by a fact of its spec (`names.rs`), with
//! how many lines each does today. Each comment names the finding of the
//! architecture review whose fix removes the entry: H1 runs-later and
//! agent-config paths, H2 the sandbox plan per format, H3 Claude Code's
//! relaxed settings keys, H4 host data in the core, H5 the Claude-only version
//! gate, H6 the scripts' own host list, M3 host names in CLI text, M4 the
//! workspace-directory message, M6 the shared end-to-end tests' literals. The
//! lists only shrink: a fix lowers or removes its entries in the same change.

/// Every crate's shared code (relative to `crates/`), outside the host
/// modules, test files and inline tests.
pub const ALLOWED_NAMES: &[(&str, usize)] = &[
    // Not in the review: the build-script attack's login path; take it from
    // the host's `protect.credentials`.
    ("openmoat-cli/src/commands/bench/proof/os.rs", 1),
    // M3: a host's name in CLI text.
    ("openmoat-cli/src/commands/proxy.rs", 1),
    ("openmoat-cli/src/sandbox/seatbelt.rs", 1),
    // Not a host: OpenMoat's own `remote/settings.json` has the same name as
    // Claude Code's settings file.
    ("openmoat-cli/src/remote/store.rs", 1),
    // H2: the per-format backends, which name their host's files and say
    // what it does; the plan reaches each through `SandboxBackend`.
    ("openmoat-cli/src/sandbox/claude.rs", 9),
    ("openmoat-cli/src/sandbox/claude/credentials.rs", 5),
    ("openmoat-cli/src/sandbox/claude/mask.rs", 3),
    ("openmoat-cli/src/sandbox/claude/nodes.rs", 1),
    ("openmoat-cli/src/sandbox/claude/rules.rs", 1),
    ("openmoat-cli/src/sandbox/claude/settings.rs", 1),
    ("openmoat-cli/src/sandbox/claude/state_dir.rs", 1),
    ("openmoat-cli/src/sandbox/codex.rs", 6),
    ("openmoat-cli/src/sandbox/codex/config.rs", 3),
    ("openmoat-cli/src/sandbox/codex/names.rs", 3),
    ("openmoat-cli/src/sandbox/codex/own_binary.rs", 7),
    ("openmoat-cli/src/sandbox/cursor.rs", 11),
    ("openmoat-cli/src/sandbox/cursor/settings.rs", 1),
];

/// The end-to-end tests every host shares (relative to
/// `crates/openmoat-cli/tests/e2e/`). M6: each writes a host's id, directory
/// or displayed text where the spec could give it: `hosts.rs`'s `dir_of`,
/// `hook_file`, `hook_path`, `hook_file_name` and `mcp_user_file`,
/// `common.rs`'s `host_fixture` and `Sandbox::guard_fixture`, `display_name`.
/// What is left is mostly text: expected output naming several agents, shell
/// command lines, a project's own agent files and `const` tables.
pub const ALLOWED_IN_SHARED_TESTS: &[(&str, usize)] = &[
    ("alias.rs", 1),
    ("allow_files.rs", 1),
    ("binary_path.rs", 2),
    ("blocks.rs", 1),
    ("check_diff.rs", 2),
    ("cli.rs", 2),
    ("config_change.rs", 13),
    ("differential.rs", 3),
    ("differential/agents.rs", 6),
    ("differential/agents/in_run.rs", 4),
    ("differential/agents/on_failure.rs", 2),
    ("differential/agents/scenarios.rs", 1),
    ("differential/scripts.rs", 8),
    ("heartbeat.rs", 3),
    ("home_screen.rs", 2),
    ("host_failures.rs", 3),
    ("human_only.rs", 2),
    ("injected.rs", 2),
    ("injected_hosts.rs", 9),
    ("install_path.rs", 10),
    ("lock_settings.rs", 1),
    ("mcp.rs", 6),
    ("mcp_init_wrap.rs", 2),
    ("mcp_startup.rs", 2),
    ("moatbench.rs", 0),
    ("project_settings_writes.rs", 17),
    ("protection.rs", 14),
    ("relay_token.rs", 1),
    ("remote_approvals.rs", 1),
    ("required_level.rs", 2),
    ("run/agent_config.rs", 30),
    ("run/agent_logins.rs", 8),
    ("run/project_paths.rs", 5),
    ("run_guard.rs", 1),
    ("sandbox.rs", 4),
    ("sandbox_exec.rs", 7),
    ("sandbox_sync.rs", 10),
    ("session_code.rs", 1),
    ("uninstall.rs", 9),
];

/// `scripts/` (relative to it).
pub const ALLOWED_IN_SCRIPTS: &[(&str, usize)] = &[
    // H6: the weekly latest-agents check's helpers, the pinned agent binaries
    // and the real-agent smoke test keep a host list of their own. The check
    // itself reads its records, written from the specs, and each record's
    // own script (`ci/latest-agents/hosts/<agent>.sh`) names only its host.
    ("ci/host-binaries.sh", 6),
    ("ci/latest-agents/after_call.py", 12),
    ("ci/latest-agents/agy_probe.py", 12),
    ("ci/latest-agents/check.py", 26),
    ("ci/latest-agents/fake_gemini.py", 3),
    ("ci/latest-agents/fake_mcp.py", 1),
    ("ci/latest-agents/fake_openai.py", 3),
    ("ci/latest-agents/test_after_call.py", 24),
    ("ci/latest-agents/test_check.py", 5),
    ("smoke-real-agents.sh", 96),
    // Not in the review: text for people (a label's description, the demo
    // recording, the "how it works" picture).
    ("ci/sync-labels.sh", 1),
    ("demo/launch-demo.sh", 6),
    ("how-it-works-svg.py", 2),
];

/// The default policy outside the blocks `tests/protect.rs` generates, by the
/// rule each line is in.
pub const ALLOWED_IN_POLICY: &[(&str, usize)] = &[
    // Not in the review: the commands that print an agent's own login (pi,
    // OpenCode); a spec fact would generate them.
    ("agent-credentials", 3),
    // Not in the review: GitHub Copilot CLI's `.github/copilot`.
    ("agent-folders", 1),
    // Not in the review: `claude setup-token`.
    ("agent-token", 1),
    // Claude Code's, Codex's and Cursor's directories and files (17 lines),
    // hand-written by design (`tests/protect.rs`), and OpenCode's and Hermes
    // Agent's commands that turn their hooks off (12 lines, not in the
    // review).
    ("kernel-self", 29),
    // Each host's command that adds an MCP server or plugin (the paths are
    // generated from the specs since ADR-091).
    ("runs-later", 14),
];

// Included with `include!` by `protect.rs` and the architecture test (no
// `#[path]` modules, AGENTS §4).
//
// The default policy's blocks that `tests/protect.rs` generates from each
// host's spec, as the lines just before and just after each block. One copy
// for every test that needs them: `protect.rs` writes the blocks between
// them, and the architecture test leaves the blocks out of its scan for host
// names. A new generated block is added here once and both tests see it.
//
// The policy's bytes are pinned (a lock pins its hash, and `openmoat policy
// upgrade` merges it line by line), so the blocks carry no markers of their
// own: each lies between two lines that are there anyway.

/// The default policy, from the repository root.
pub const POLICY: &str = "crates/openmoat-core/policies/default-v1.yaml";

/// The `kernel-self` lines just before and just after the generated block.
pub const POLICY_BEFORE: &str = "      - \"**/.codex/hooks.json\"\n";
pub const POLICY_AFTER: &str = "      - \"**/.moat/**\"\n";

/// The `agent-credentials` lines just before and just after its paths.
pub const CREDENTIALS_BEFORE: &str = "    fs.read: &agent-credentials\n";
pub const CREDENTIALS_AFTER: &str = "    fs.write: *agent-credentials\n";

/// The `runs-later` rule's comment line just before the hosts' paths, and the
/// comment of the rule's own paths that follow them.
pub const RUNS_LATER_BEFORE: &str =
    "      # each agent's files that run later, generated from its spec\n";
pub const RUNS_LATER_AFTER: &str =
    "      # a virtual environment's interpreter and scripts, which the editor's\n";

/// `project-fs`'s comment line just before the hosts' project paths, and the
/// comment of the exceptions that follow them.
pub const PROJECT_FS_BEFORE: &str = "      # each agent's files in a project that run later (`runs-later` needs review), from its spec\n";
pub const PROJECT_FS_AFTER: &str =
    "      # a virtual environment's interpreter and a dev container's host command\n";

/// Every generated block of the default policy, as (before, after).
pub const BLOCKS: &[(&str, &str)] = &[
    (POLICY_BEFORE, POLICY_AFTER),
    (CREDENTIALS_BEFORE, CREDENTIALS_AFTER),
    (RUNS_LATER_BEFORE, RUNS_LATER_AFTER),
    (PROJECT_FS_BEFORE, PROJECT_FS_AFTER),
];

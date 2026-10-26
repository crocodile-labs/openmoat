//! Hermes Agent's files the default policy and the taint list protect, and
//! its processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "Hermes Agent: its home: the `config.yaml` that holds OpenMoat's hook, the\n\
         hook allowlist without which a gateway, cron or ACP session skips it, the\n\
         `.env` that can set `HERMES_SAFE_MODE`, the sticky profile, the plugins and\n\
         hooks it runs in its own process, and the folder of its profiles (another\n\
         profile's files ask, `runs-later`; `HERMES_HOME` moves these to the one in use)",
        &[
            "~/.hermes",
            "~/.hermes/config.yaml",
            "~/.hermes/shell-hooks-allowlist.json",
            "~/.hermes/.env",
            "~/.hermes/active_profile",
            "~/.hermes/plugins",
            "~/.hermes/plugins/**",
            "~/.hermes/hooks",
            "~/.hermes/hooks/**",
            "~/.hermes/agent-hooks",
            "~/.hermes/agent-hooks/**",
            "~/.hermes/profiles",
        ],
    )],
    taint: &[Paths::new(
        "Hermes Agent: the skills, cron jobs, memories and persona it loads into\n\
         later sessions, and a project's `.hermes.md` and plugins",
        &[
            "~/.hermes/skills/**",
            "~/.hermes/cron/**",
            "~/.hermes/memories/**",
            "~/.hermes/SOUL.md",
            "**/.hermes.md",
            "**/.hermes/**",
        ],
    )],
    credentials: &[Paths::new(
        "Hermes Agent: the secret files and folders its own file tools refuse\n\
         (`agent/file_safety.py`; its `.env` is `secrets-paths`'), in its home and\n\
         in each profile; its terminal tool reaches them, which this rule closes",
        &[
            "~/.hermes/auth.json",
            "~/.hermes/auth.lock",
            "~/.hermes/.anthropic_oauth.json",
            "~/.hermes/webhook_subscriptions.json",
            "~/.hermes/auth/google_oauth.json",
            "~/.hermes/cache/bws_cache.json",
            "~/.hermes/mcp-tokens/**",
            "~/.hermes/vault/**",
            "~/.hermes/webapp/**",
            "~/.hermes/browser-profile/**",
            "~/.hermes/profiles/*/auth.json",
            "~/.hermes/profiles/*/.anthropic_oauth.json",
            "~/.hermes/profiles/*/webhook_subscriptions.json",
            "~/.hermes/profiles/*/auth/google_oauth.json",
            "~/.hermes/profiles/*/cache/bws_cache.json",
            "~/.hermes/profiles/*/mcp-tokens/**",
            "~/.hermes/profiles/*/vault/**",
            "~/.hermes/profiles/*/webapp/**",
            "~/.hermes/profiles/*/browser-profile/**",
        ],
    )],
};

/// `hermes` is a Python entry point (`hermes_cli.main:main`), so a session
/// shows as `hermes` or as Python running it from the `hermes_cli` package.
pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["hermes"],
    package_dirs: &[&["hermes_cli"]],
    helper: None,
};

//! End-to-end tests of the `moat` binary, one test target for all of them.
//!
//! Every test runs the real binary in an isolated home (`HOME`, `USERPROFILE`
//! and the process environment cleared), never the developer's own `~`, and
//! never the network.

mod common;

mod alias;
mod allow;
mod allow_expiry;
mod allow_files;
mod anchor;
mod antigravity_cli;
mod approvals;
mod audit;
#[cfg(unix)]
mod binary_path;
mod blocks;
mod canary;
mod check_diff;
mod cli;
mod cline;
mod closed_pipe;
mod codex;
mod config_change;
mod continue_cli;
mod copilot_cli;
mod cursor;
mod cursor_sandbox;
mod differential;
mod edit;
mod escapes;
mod export;
mod gemini_cli;
mod goose;
mod guard;
mod heartbeat;
mod hermes;
mod home_screen;
mod host_failures;
mod hosts;
#[cfg(unix)]
mod human_only;
mod injected;
#[cfg(unix)]
mod install_path;
mod listings;
mod lock;
mod lock_settings;
mod mcp;
mod mcp_gateway;
mod mcp_startup;
mod moatbench;
mod openclaw;
mod opencode;
#[cfg(unix)]
mod packs;
mod paths;
mod permission_mode;
mod pi;
mod policy_upgrade;
mod project_settings_writes;
mod protection;
mod provenance;
mod provenance_notes;
mod proxy;
mod proxy_ca;
mod proxy_session;
mod push;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod relay_token;
mod replay_report;
mod repo_policy;
mod required_level;
mod run;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod run_guard;
mod sandbox;
#[cfg(unix)]
mod sandbox_exec;
mod sandbox_sync;
mod secret;
mod serve;
mod session_code;
mod staging;
mod taint;
mod taint_answered;
mod team;
mod trust;
mod uninstall;

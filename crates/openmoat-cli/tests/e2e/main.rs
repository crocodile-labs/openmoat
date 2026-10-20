//! End-to-end tests of the `moat` binary, one test target for all of them.
//!
//! Every test runs the real binary in an isolated home (`HOME`, `USERPROFILE`
//! and the process environment cleared), never the developer's own `~`, and
//! never the network.

mod common;

mod alias;
mod allow;
mod allow_files;
mod anchor;
mod approvals;
mod audit;
#[cfg(unix)]
mod binary_path;
mod canary;
mod cli;
mod closed_pipe;
mod codex;
mod config_change;
mod continue_cli;
mod cursor;
mod cursor_sandbox;
mod differential;
mod edit;
mod escapes;
mod export;
mod guard;
mod home_screen;
mod host_failures;
#[cfg(unix)]
mod human_only;
#[cfg(unix)]
mod install_path;
mod listings;
mod lock;
mod lock_settings;
mod mcp;
mod moatbench;
mod openclaw;
#[cfg(unix)]
mod packs;
mod paths;
mod permission_mode;
mod policy_upgrade;
mod protection;
mod provenance;
mod proxy;
mod push;
mod replay_report;
mod repo_policy;
mod run;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod run_guard;
mod sandbox;
#[cfg(unix)]
mod sandbox_exec;
mod sandbox_sync;
mod secret;
mod taint;
mod taint_answered;
mod team;
mod trust;
mod uninstall;

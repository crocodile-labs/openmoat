//! End-to-end tests of the `moat` binary, one test target for all of them.
//!
//! Every test runs the real binary in an isolated home (`HOME`, `USERPROFILE`
//! and the process environment cleared), never the developer's own `~`, and
//! never the network.

mod common;

mod allow;
mod allow_files;
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
mod install_path;
mod lock;
mod moatbench;
mod paths;
mod policy_upgrade;
mod protection;
mod proxy;
mod replay_report;
mod repo_policy;
mod run;
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

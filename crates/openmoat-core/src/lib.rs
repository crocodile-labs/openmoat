//! `openmoat-core`: the trusted decision core of OpenMoat.
//!
//! This crate is **pure**: it performs no I/O and makes no OS calls. Callers
//! (the CLI, host adapters) read files, resolve the environment and pass
//! everything in. That keeps the security-relevant logic small, testable and
//! portable (it also builds for `wasm32`).
//!
//! Pipeline: an [`Action`] is classified into [`AtomicAction`]s, each atomic
//! action is evaluated `deny → allow → ask → defaults` by a [`CompiledPolicy`],
//! and the strictest verdict across them becomes the [`Decision`]. Facts that
//! need the filesystem reach the engine through [`ProgramResolver`] and
//! [`PathResolver`]. The policy compiler ([`ir::lower()`]) derives from the same
//! policy what an operating-system layer can enforce (ADR-019).

#![warn(missing_docs)]
// A library reports to its caller; only the `moat` binary prints.
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod action;
mod engine;
mod expand;
mod host;
pub mod ir;
mod kind;
// Public only for the differential test against bash (`tests/lexer_vs_bash.rs`);
// not a stable API.
#[doc(hidden)]
pub mod lexer;
pub mod lint;
mod packages;
mod patch;
mod paths;
mod pattern;
mod policy;
mod programs;
mod realpath;
mod repo;
mod secret;
mod shell;
mod taint;
pub mod token;
mod verdict;
pub mod yaml;

pub use action::{Action, AtomicAction};
// The taint `Secret` (material a session read) is exported as `TaintSecret`, apart
// from the policy's brokered `Secret`.
pub use engine::{CompiledPolicy, EvalContext, Secret as TaintSecret, TAINT_RULE, Taint, evaluate};
pub use host::{
    MAX_DNS_LABEL_LEN, MAX_DNS_NAME_LEN, file_url_path, malformed_port_pattern, port_pattern,
};
pub use kind::{Kind, UnknownKind};
pub use patch::writes as patch_writes;
pub use paths::resolve as resolve_path;
pub use pattern::literal_shell_pattern;
pub use policy::{Defaults, McpSettings, Policy, PolicyError, RuleGroup, SandboxSettings};
pub use programs::{MapResolver, NoResolver, ProgramResolver};
pub use realpath::{MapPathResolver, PathResolver};
pub use repo::{REPO_RULE_PREFIX, RepoPolicy};
pub use secret::{SECRET_RULE_PREFIX, Secret, Source as SecretSource};
pub use shell::installs::near_miss_atoms as package_near_misses;
pub use shell::push::Push;
pub use taint::TaintSettings;
pub use verdict::{Decision, UnknownVerdict, Verdict};

/// The shipped default policy, as YAML: what `moat init` installs and what the
/// conformance suite pins. Parse it with [`Policy::parse`].
pub const DEFAULT_POLICY: &str = include_str!("../policies/default-v1.yaml");

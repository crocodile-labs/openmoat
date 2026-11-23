//! `openmoat-core`: the trusted decision core of OpenMoat.
//!
//! This crate is **pure**: it performs no I/O and makes no OS calls. Callers
//! (the CLI, host adapters) read files, resolve the environment and pass
//! everything in. That keeps the security-relevant logic small, testable and
//! portable (it also builds for `wasm32`).
//!
//! Pipeline: an [`Action`] is classified into [`AtomicAction`]s, each atomic
//! action is evaluated `deny → allow → review → defaults` by a [`CompiledPolicy`],
//! and the strictest verdict across them becomes the [`Decision`]. Facts that
//! need the filesystem reach the engine through [`ProgramResolver`] and
//! [`PathResolver`]. The policy compiler ([`ir::lower()`]) derives from the same
//! policy what an operating-system layer can enforce (ADR-019).

#![warn(missing_docs)]
// A library reports to its caller; only the `moat` binary prints.
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod action;
mod arguments;
pub mod attribution;
pub mod boundary;
pub mod canary;
pub mod diffscan;
mod engine;
mod expand;
mod host;
mod injection;
pub mod ir;
mod kind;
// Public only for the differential test against bash (`tests/lexer_vs_bash.rs`);
// not a stable API.
#[doc(hidden)]
pub mod lexer;
pub mod lint;
pub mod mcp_flow;
mod packages;
mod patch;
mod paths;
mod pattern;
mod personal;
mod policy;
mod predicate;
mod programs;
mod realpath;
mod repo;
mod requests;
mod route;
pub mod rule_id;
mod secret;
mod shell;
mod staging;
mod taint;
pub mod token;
mod verdict;
pub mod widen;
pub mod yaml;

pub use action::{Action, AtomicAction};
pub use arguments::{
    Arguments, MAX_VALUE_BYTES as MAX_ARGUMENT_VALUE_BYTES, MAX_VALUES as MAX_ARGUMENT_VALUES,
    snake as argument_key,
};
// The taint `Secret` (material a session read) is exported as `TaintSecret`, apart
// from the policy's brokered `Secret`.
pub use engine::{
    CompiledPolicy, EvalContext, STAGING_ATOM, Secret as TaintSecret, Staging, Taint,
    UntrustedKind, evaluate,
};
pub use host::{
    MAX_DNS_LABEL_LEN, MAX_DNS_NAME_LEN, file_url_path, malformed_port_pattern, port_pattern,
};
pub use injection::{
    InjectedLookup, InjectedMap, MAX_SCANNED_BYTES as MAX_INJECTED_SCAN_BYTES,
    MAX_TOKENS_PER_OUTPUT as MAX_INJECTED_TOKENS_PER_OUTPUT, Token as InjectedToken,
    TokenKind as InjectedTokenKind,
};
pub use kind::{Kind, UnknownKind};
pub use packages::Ecosystem;
pub use patch::{Replayed as PatchReplayed, replay as patch_replay, writes as patch_writes};
pub use paths::resolve as resolve_path;
pub use pattern::literal_shell_pattern;
pub use policy::{
    BrowserOpen, DeclaredVersion, Defaults, ForeignHooks, HookSettings, McpSettings, OldNames,
    Policy, PolicyError, ProjectHookOff, ProjectTop, Require, RequiredBy, RequiredLevel,
    Requirement, RuleGroup, RunBoundary, RunEnv, SUPPORTED_VERSION, SandboxSettings,
    TITLE_MAX_CHARS, Unattended, WHY_MAX_CHARS, declared_version, env_name_problem,
};
pub use predicate::{ArgNames, Predicate, Provenance};
pub use programs::{MapResolver, NoResolver, ProgramResolver};
pub use realpath::{MapPathResolver, PathResolver};
pub use repo::{REPO_RULE_PREFIX, RepoPolicy};
pub use requests::{
    REQUESTS_RULE_PREFIX, RequestCheck, RequestEntry, RequestRules, Untrusted as RequestsUntrusted,
};
pub use secret::{
    CommandHome as SecretCommandHome, CommandSource as SecretCommand, METHOD_OVERRIDE_HEADERS,
    PathRefusal, Permit, RequestPath, Route as SecretRoute, SECRET_RULE_PREFIX, Secret,
    Source as SecretSource, Tls as SecretTls,
};
pub use shell::cwd::leaves_unknown_directory;
pub use shell::installs::package_atoms;
pub use shell::push::Push;
pub use shell::replaced::replaced_files;
pub use staging::{DEFAULT_OUTSIDE_FOLDERS, DEFAULT_OUTSIDE_READS, StagingSettings};
pub use taint::{TaintSettings, TrifectaVerdict};
pub use verdict::{Decision, Notice, OLD_REVIEW, UnknownVerdict, Verdict};

/// The shipped default policy, as YAML: what `moat init` installs and what the
/// conformance suite pins. Parse it with [`Policy::parse`].
pub const DEFAULT_POLICY: &str = include_str!("../policies/default-v1.yaml");

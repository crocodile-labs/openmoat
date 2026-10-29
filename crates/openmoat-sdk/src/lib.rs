//! `openmoat-sdk`: OpenMoat's policy decisions for your own agent product.
//!
//! Compile a policy once, then ask before every tool call your agent makes
//! whether it may run:
//!
//! ```
//! use openmoat_sdk::{Action, Context, DEFAULT_POLICY, Engine, Policy, Verdict};
//!
//! let policy = Policy::parse(DEFAULT_POLICY)?;
//! let engine = Engine::new(policy, &Context::new("/home/me", "/home/me/app").project("/home/me/app"))?;
//!
//! let decision = engine.decide(&Action::shell("cat ~/.ssh/id_rsa"));
//! assert_eq!(decision.verdict, Verdict::Deny);
//! assert_eq!(decision.rules, ["secrets-paths"]);
//! # Ok::<(), openmoat_sdk::Error>(())
//! ```
//!
//! **The SDK decides; enforcement is yours.** A call it denies must not run, and
//! a call it asks about must not run until a person approves that exact call.
//! Nothing here starts, stops or confines a process: this is not a sandbox
//! (docs/SDK.md, ADR-046). Run exactly the action you decided, never a value
//! rebuilt from it afterwards.
//!
//! The crate does no I/O. Facts that live on a filesystem (where a program
//! resolves, where a symlink points, which files a glob names) come in as
//! [`Facts`]; the history of a session as a [`Session`]. With the `fs`
//! feature, `Policy::read` reads a policy file.
//!
//! What is stable, and how this crate keeps in step with the `openmoat` CLI, is
//! ADR-046: the decision API, the action and verdict shapes, the rule ids a
//! decision names and the policy schema version.

#![warn(missing_docs)]
// A library reports to its caller; it never prints.
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod action;
mod context;
mod decision;
mod engine;
mod error;
mod facts;
#[cfg(feature = "fs")]
mod fs;
mod policy;
mod session;

pub use action::{Action, McpCall, UnknownToolCall};
pub use context::Context;
pub use decision::{Decision, Verdict};
pub use engine::Engine;
pub use error::Error;
pub use facts::Facts;
pub use policy::Policy;
pub use session::Session;

/// The shipped default policy, as YAML: the one `openmoat init` installs and the
/// conformance suite pins. Parse it with [`Policy::parse`].
pub const DEFAULT_POLICY: &str = openmoat_core::DEFAULT_POLICY;

/// The policy schema version (`version:` in a policy) this release reads.
pub const POLICY_SCHEMA_VERSION: u32 = openmoat_core::SUPPORTED_VERSION;

/// This crate's version, the same as the OpenMoat release it was built from.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

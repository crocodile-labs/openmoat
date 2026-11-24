//! `openmoat credential`: the local helper `openmoat run` sets up for git and
//! the AWS tools (ADR-118). They start it; people do not.

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum CredentialCommand {
    /// git's credential helper for secret `id`: git runs it with `get`, `store` or
    /// `erase` and the request on standard input. Only `get` asks the proxy.
    Git {
        /// The brokered secret, as the policy names it.
        id: String,
        /// What git asks: `get`, `store` or `erase`.
        operation: String,
    },
    /// The AWS tools' `credential_process` for secret `id`: prints the minted
    /// session's credentials as the AWS tools read them.
    Aws {
        /// The brokered secret, as the policy names it.
        id: String,
    },
}

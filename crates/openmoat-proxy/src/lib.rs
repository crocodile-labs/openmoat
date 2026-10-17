//! `openmoat-proxy`: the default-deny egress proxy behind `moat proxy` (ADR-020).
//!
//! It serves HTTP `CONNECT` tunnels and absolute-form plain-HTTP requests on a
//! loopback port:
//!
//! - Hosts are decided by openmoat-core's [`CompiledPolicy`](openmoat_core::CompiledPolicy)
//!   as `moat guard` decides a fetch tool's URL: only an `allow` passes.
//! - Cloud metadata and link-local addresses are refused whatever the policy
//!   says, by name and on every address the proxy resolves. Private and CGNAT
//!   addresses are refused unless an allow rule names the address.
//! - A tunnel's TLS `ClientHello` must name the CONNECT host (SNI); nothing is
//!   decrypted.
//! - A request that carries a brokered secret's placeholder or value to a host
//!   other than the secret's own is refused ([`Broker`]).
//! - Every decision is recorded through a [`Recorder`]; a failed record is a
//!   refused connection.
//!
//! Plain `std::net` and one thread per connection, capped by [`Limits`]; the
//! choice is explained in `docs/ARCHITECTURE.md` §12.

#![warn(missing_docs)]
// A library reports to its caller; only the `moat` binary prints.
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod audit;
mod body;
mod broker;
mod decide;
mod request;
mod server;
mod sni;
mod tunnel;
mod upstream;

pub use audit::{Connection, RecordError, Recorder};
pub use broker::{Broker, BrokerError, Carried, Leak, RULE_SECRET};
pub use decide::{
    Forbidden, RULE_ADDRESS, RULE_AUDIT, RULE_REQUEST, RULE_SNI, RULE_UPSTREAM, address_policy,
    forbidden, host as decide_host, named as address_named,
};
pub use request::{MAX_HEADERS, Request, RequestError, Target, parse as parse_request};
pub use server::{Limits, Proxy};
pub use sni::{Hello, HelloError, MAX_HELLO, server_name};
pub use upstream::{Refusal, Resolve, SystemResolver, connect};

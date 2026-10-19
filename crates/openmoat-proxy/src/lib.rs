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
//! - In session mode ([`Sessions`], ADR-027) every request must carry its
//!   session's credential. The session's audit id goes on each row, a
//!   session that read secret material reaches only that secret's host, and
//!   no session holds more than half the connections.
//! - A connection that starts with a [`LocalService`]'s prefix goes to that
//!   service of the proxy's own process (ADR-028), not upstream.
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
mod local;
mod request;
mod server;
mod session;
mod slots;
mod sni;
mod tunnel;
mod upstream;

pub use audit::{Connection, RecordError, Recorder};
pub use broker::{Broker, BrokerError, Carried, Leak, RULE_SECRET};
pub use decide::{
    Forbidden, RULE_ADDRESS, RULE_AUDIT, RULE_REQUEST, RULE_SNI, RULE_UPSTREAM, address_policy,
    denied as address_denied, forbidden, host as decide_host, named as address_named,
    tainted as decide_tainted,
};
pub use local::LocalService;
pub use request::{
    MAX_HEADERS, ProxyCredential, Request, RequestError, Target, parse as parse_request,
};
pub use server::{Limits, Proxy};
pub use session::{
    AuthError, Credential, CredentialError, MIN_TOKEN_LEN, RULE_SESSION, Sessions, TaintLookup,
    constant_time_eq,
};
pub use sni::{Hello, HelloError, MAX_HELLO, server_name};
pub use upstream::{Refusal, Resolve, SystemResolver, connect};

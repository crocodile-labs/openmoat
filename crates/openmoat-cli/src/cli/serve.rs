//! `openmoat serve` grammar (ADR-066).

use std::net::SocketAddr;

use clap::Args;

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Address to listen on: `127.0.0.1:<port>` or `[::1]:<port>`, nothing else, so
    /// no other machine can reach it. Port 0, the default, takes a free one.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:0")]
    pub listen: SocketAddr,
}

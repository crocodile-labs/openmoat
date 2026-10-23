# openmoat-proxy

The default-deny egress proxy behind `openmoat proxy` and `openmoat run` (ADR-020): HTTP `CONNECT` tunnels and absolute-form plain-HTTP requests on a loopback port, hosts decided by `openmoat-core` the way `guard` decides a fetch URL, and the secret broker (`broker/`). Root rules: [AGENTS.md](../../AGENTS.md).

## Rules
- Network through `std::net` only; no async runtime, no storage. Dependencies stay `openmoat-core`, `httparse`, `thiserror`, `zeroize`.
- Only an `allow` passes. Cloud metadata and link-local addresses are refused whatever the policy says, by name and on every resolved address; private and CGNAT addresses only when an allow rule names the address.
- A tunnel's TLS `ClientHello` must name the CONNECT host (SNI). Nothing is decrypted.
- A connection that cannot be recorded is refused; recording goes through the `Recorder` trait the CLI implements (`Recorder::unrecorded`), never by printing.
- A brokered secret's placeholder or value sent to any host other than its own is refused. Secret buffers are zeroised.
- An open tunnel is checked again against its session's taint at every recheck; a cached taint is reused only while `TaintLookup::version` is unchanged.
- Typed `thiserror` errors; every public item has a doc comment.

## Test
- `cargo test -p openmoat-proxy`: unit tests and `tests/proxy/` (`broker`, `http`, `limits`, `private`, `sessions`, `tunnel`). The tests bind loopback sockets; a sandbox that forbids binding fails them for that reason only.
- Every widening (a new allowed address class, a relaxed SNI check) carries an attack test for the skipped case as a host, an address and a redirect.

## Do not
- Add a dependency on an async runtime or a TLS library.
- Pass a request whose decision or record failed.

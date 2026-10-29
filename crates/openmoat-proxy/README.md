# openmoat-proxy

The default-deny egress proxy behind `openmoat proxy` and `openmoat run` (ADR-020).

It serves HTTP `CONNECT` tunnels and absolute-form plain-HTTP requests on a loopback
port:

- Every request belongs to an agent session: it carries a per-session proxy credential,
  one the proxy holds (`openmoat run`, ADR-027) or one a `Verify` accepts (the standalone
  `openmoat proxy`, ADR-044), and a request without a valid one is refused
  (`proxy-session`) before its host is decided. The session selects the taint and the
  share of the connections that apply.
- Hosts are decided by `openmoat-core` the way `openmoat guard` decides a fetch tool's
  URL: only an `allow` passes.
- Cloud metadata and link-local addresses are refused whatever the policy says, by
  name and on every address the proxy resolves. Private and CGNAT addresses are
  refused unless an allow rule names the address.
- A tunnel's TLS `ClientHello` must name the CONNECT host (SNI). Nothing is decrypted, except a tunnel to the host of a secret that says `tls: terminate`, in `openmoat run` (ADR-043, `tls.rs`, `exchange.rs`): one request read, checked against the leak check and the secret's `allow` rules, the value added, the upstream verified with the CONNECT host as the name, the answer searched for every value before the client gets it.
- A request that carries a brokered secret's placeholder or value to a host other
  than the secret's own is refused (`Broker`).
- Every decision is recorded through a `Recorder`; a connection that cannot be
  recorded is refused.

Plain `std::net` and one thread per connection, capped by `Limits`; no async runtime
and no storage. Part of [OpenMoat](https://github.com/crocodile-labs/openmoat).

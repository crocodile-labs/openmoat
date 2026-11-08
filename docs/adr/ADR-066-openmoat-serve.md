# ADR-066: `openmoat serve`, a read-only view on 127.0.0.1 with a token for the run

Status: accepted · Date: 2026-11-08 · Builds on ADR-013 (the 1.0 stage names `serve`),
ADR-014 (person-only commands), ADR-059 (`watch` and `why`) · Closes #320

## Context

ADR-013 lists `serve` among what 1.0 needs: a person should be able to read what
`openmoat status`, `show`, `report` and `why` say in a browser, beside the agent, without
typing commands. A local web server is an easy thing to get wrong, and this one would
serve the audit log: every command, path and host the agents used.

The attackers that matter:

1. **Another web page in the person's browser.** It can send requests to
   `http://127.0.0.1:<port>/` (cross-site requests, a form, an image), and through **DNS
   rebinding** it can make its own name resolve to 127.0.0.1 and read the answers as same
   origin.
2. **Another local program or user** that connects to the port.
3. **Another machine**, if the server listened beyond loopback.
4. **The agent itself**: starting a long-lived listener, or reading the link from its own
   output and then the audit log through it, or using it to change something.

## Decision

`openmoat serve [--listen 127.0.0.1:<port> | [::1]:<port>]`:

1. **Loopback only.** It binds exactly `127.0.0.1` or `::1` (port 0, the default, takes a
   free one). Any other address is refused before anything is opened, other loopback
   addresses (`127.0.0.2`) and IPv4-mapped forms included, so the address in the link is
   the only one it listens on. A connection whose peer is not on loopback is closed unanswered.
2. **A token for the run.** At start it reads 32 bytes from the OS random source
   (`getrandom`, as the proxy session key does), prints them once as hex in the link
   `http://127.0.0.1:<port>/?token=<hex>`, and keeps them only in memory (zeroised on drop).
   They are never written to a file, the audit log or stderr, and stop working when the
   process stops. Every request must carry the token, as the `token` query parameter (the
   links in the pages carry it) or as `Authorization: Bearer <token>` (scripts). It is
   compared in constant time (`openmoat_proxy::constant_time_eq`). Without it, every path,
   the stylesheet included, is a 401 that says nothing about what is there.
3. **No cookie.** A cookie on 127.0.0.1 is sent to every port of that host, so another local
   server the browser visits would receive it. The token travels in the URL instead; the
   pages set `Referrer-Policy: no-referrer` and load nothing but the server's own
   stylesheet, so the URL is not sent anywhere else.
4. **Checks before anything is read**, in this order:
   - `Host` must be `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` (bare names
     only on port 80); anything else, or none, is 403. This defeats DNS rebinding: the
     rebound page sends its own name.
   - `Origin`, when sent, must be `http://` and one of those names; `Sec-Fetch-Site`, when
     sent, must be `same-origin` or `none`. Another site's request is 403 even with a leaked
     token.
   - Only `GET`, without a body (`Content-Length` other than 0 or any
     `Transfer-Encoding` is 400). Other methods are 405.
   - A header that decides any of this (`Host`, `Origin`, `Sec-Fetch-Site`,
     `Authorization`) given twice, a query parameter given twice, or bad percent-encoding is
     400: a request that could be read two ways is refused.
   - Then the token.
5. **Every response** carries `Content-Security-Policy: default-src 'none'; style-src
   'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `Cache-Control:
   no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
   `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, and
   `Connection: close`. It never sends `Access-Control-*` headers (no CORS) and never sets a
   cookie. The pages hold no script.
6. **Strictly read-only, through the commands' own builders.** `/` and `/status` are
   `openmoat status --format json` (with the latest decisions), `/show` is `openmoat show`
   (`id`, `session`, `since`, `recent`), `/report` is `openmoat report` (`since`, `host`),
   `/why` is `openmoat why` (`event`). Each is also under `/api/` as exactly the JSON the
   command's `--format json` prints: the commands' JSON is built by one function each
   (`status::json`, `show::events`, `report::json`, `why::json`) that both the command and
   the server call. The audit log is opened read-only, as by those commands, and what it
   holds was masked when it was recorded, so nothing is unmasked here. Text from the log is
   cleaned as on a terminal (`render::clean_lines`, which also turns bidirectional
   overrides into `?`) and HTML-escaped. No path runs `allow`, `doctor --accept`, `trust`
   or any other command that changes state, and an unknown path or parameter is 404 or 400.
7. **A person's command.** It refuses to start when an agent is among its parent processes
   or the binary is not the one the lock records (`terminal::refuse_agent`), and without
   an interactive terminal, as `openmoat allow` and the other person-only commands do. The
   default policy's `kernel-self` rule denies `openmoat serve` and `moat serve`, by name and
   by path, and quoted inside the pty wrappers (`script`, `expect`, `tmux`, `screen`,
   `osascript`, Python's `pty.spawn`); `openmoat serve --help` stays allowed
   (`openmoat-readonly`). An agent must not start a listener that outlives its call, nor
   hold a link that reads the whole log of every session, its own included.
8. **Bounded.** A request head is at most 8 KiB (431 beyond), a connection gets 5 seconds
   to send it, at most 8 connections are answered at once, and each is answered on its own
   thread from a fresh read of the files.

### Dependencies

No new crate. The request head is parsed with `httparse`, which the workspace already
locks and `cargo-deny` already checks for `openmoat-proxy`; the CLI now depends on it as
well. Hand-parsing HTTP is where request smuggling and header confusion come from, and
`httparse` is the parser the proxy already trusts. Everything else is `std::net`,
`std::thread` and crates the CLI has (`getrandom`, `zeroize`, `serde_json`).

## Consequences

- A person can keep a tab open on what the agents did and why, refreshed by reloading.
- The link is a credential for reading the audit log while the server runs. The terminal
  says so when it prints it. Browser history holds it; it is useless once the server stops.
- Another program running as the same user could already read `~/.moat/audit.db`; the
  server adds no access for it. Another user on the machine, a web page and another machine
  get nothing without the token.
- Not done: live updates (a page reloads), HTTPS on loopback (no certificate a browser
  trusts without a CA install, which ADR-043 keeps to `openmoat run`), and any command
  that changes state from the browser. A later ADR must decide those, and any state change
  would need a person-at-the-terminal confirmation that a browser cannot give.
- Tests: unit tests for the address refusal, the token, the `Host`, `Origin` and
  `Sec-Fetch-Site` checks, the methods, the parsing and the headers
  (`commands/serve/tests.rs`); an end-to-end test that starts the binary, reads the link
  and checks the answers over a real socket (`tests/e2e/serve.rs`, where the platform lets
  a test listen on loopback, as CI does); attack fixtures for the `kernel-self` denials.

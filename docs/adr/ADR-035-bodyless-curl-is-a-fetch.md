# ADR-035: A `curl` or `wget` that sends nothing is a `fetch`

Status: accepted · Date: 2026-10-19 · Refines ADR-017

## Context

ADR-017 made a host's own fetch tool (`WebFetch`) a narrower kind of `net`, so a
`WebFetch` of `https://docs.rs/serde` defers to the agent's prompt while the same URL
through `curl` is denied by `default.net`. The reason was that a shell client can send
anything: a body, headers, a file. But most `curl` and `wget` calls an agent makes are
plain downloads, and denying `curl https://docs.rs/serde` while allowing the agent to
read the same page another way is friction with no protection behind it: it pushes
people to allow whole hosts or turn the `net` default off.

## Decision

- The classifier emits `fetch` atoms instead of `net` atoms for a `curl` or `wget`
  command that provably sends nothing but its URLs (`shell/commands/fetch.rs`). The check
  is an allowlist: every word is a URL or an option known to send nothing; no word the
  shell expands; no `@` in a value or a URL's user part; no variable set earlier on the
  line that points the program at another configuration file or a proxy; and the host is
  a domain name, not an IP address in any spelling or a single-label name. A command
  that follows redirects stays `net`: `curl -L`/`--location`, and `wget` unless its last
  `--max-redirect` is `0`, since wget follows redirects by default. A redirect leads
  where the hook cannot see, a link-local metadata address included, and `WebFetch`
  does not follow one to another host. Anything else,
  an option the list does not know included, keeps the command `net`.
- Nothing else changes: `net` deny rules still match these fetches (`cloud-metadata`,
  `token-egress`), `local-net` and `registries` still apply, and a `fetch` atom is
  untrusted content for session taint, as a `WebFetch` is.

## Consequences

- `curl https://docs.rs/serde`, `curl -sS https://example.com/f.txt -o f.txt` and
  `wget --max-redirect=0 https://example.com/a.tar.gz` defer under the default policy; every form that can
  send data stays denied for unlisted hosts.
- A `fetch` allow or deny in a policy now also covers these commands, not only the fetch
  tool; ADR-017's "without opening it to shell clients" holds only for clients that may
  send data.
- A `curl` or `wget` to an allowed host now taints the session as untrusted content, so
  a later write to a protected path asks.
- `curl -sSL` and a plain `wget` of an unlisted host stay denied, as before.
- Residual risk, as for `WebFetch`: data the agent writes into the URL itself; a name
  that resolves to an internal address; a `~/.curlrc` or `~/.wgetrc` written earlier,
  which may add options (following redirects among them). The hook cannot see where DNS
  leads; under `moat run` and the host sandboxes the
  proxy refuses link-local and metadata addresses after DNS.

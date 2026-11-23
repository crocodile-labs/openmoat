# ADR-112: Default rules from outside benchmarks

Status: accepted · Date: 2026-11-22 · Builds on ADR-017 (fetch is a narrower `net`),
ADR-025 (defer to the agent's prompt), ADR-035 (`curl` that sends nothing is a fetch),
ADR-047 (a page open is a fetch), ADR-052 (personal data on its way out)

## Context

[BENCHMARKS.md](../BENCHMARKS.md) measured the default policy of 0.25.0 against two
attack sets written by others, RedCode-Exec and agent-egress-bench, through `openmoat
policy check`. Most of what was not stopped is out of reach of a tool-call check (a
script written to a file and then run, logic bugs, content an agent receives). The
rest were plain gaps in the default rules, listed in "What these results show":

1. `/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd` and the SSH server's host
   private keys were not secret paths.
2. Writes, deletes and moves in the operating system's folders (`rm /etc/passwd`,
   `cp … /usr/copy_file`) deferred.
3. `persistence` named the user's LaunchAgents and systemd folder, not the system's
   schedulers and service managers, nor `systemctl enable` and `launchctl load`.
4. A fetch tool's URL with an IP address in any spelling (`0x7f000001`, `10.0.0.1`,
   `[::ffff:127.0.0.1]`) deferred, where `curl` to it was denied: `Action::Fetch` made
   every host a `fetch` atom, while the shell classifier and a browser page open
   (ADR-047) keep an address `net`. Neither read the URLs inside a URL
   (`?target=http://169.254.169.254/`), which a relay or redirect reaches.
5. `token-egress` knew prefixed formats only: no GitLab deploy or runner token, no
   AWS secret key by name, no JWT, no database URL with a password, no private key.
6. Known tokens encoded in a URL (base64, hex, URL-encoded once or more) pass before
   the session read a secret; `encoded-egress` needs taint.
7. Data carried in a host name (`<hex>.exfil.example`).
8. A download into a system folder (`wget -O /usr/x.py URL`) and `curl $url`.
9. `pkill`, `killall` and `kill` of system processes deferred.

## Decision

Every change adds a `deny` or a `review`; none loosens a verdict. Each carries the
benchmark's cases as attack fixtures and the everyday forms beside them as benign
fixtures (`tests/conformance/`, the `*-bench-*` ids).

1. **System credential files** join `secrets-paths`: `/etc/{shadow,shadow-,gshadow,
   gshadow-,master.passwd,security/opasswd}` and
   `/etc/ssh/ssh_host_{rsa,dsa,ecdsa,ed25519}_key`, also under `/private/etc`. Literal
   names, not globs, so no sandbox is asked to list `/etc`. `/etc/passwd` and the
   `.pub` keys are world-readable and stay out.
2. **`system-files`** (review) holds `fs.write` in `/etc`, `/private/etc`, `/usr`
   except `/usr/local`, `/bin`, `/sbin`, `/lib*`, `/boot`, `/System` and the system
   parts of `/Library`. A path rule, so every spelling the classifier already turns
   into a write is covered (`rm`, `cp`/`mv`/`install`/`ln` targets, `tee`, `>`,
   `chmod`, `chown`, `curl -o`, `wget -O`, file tools). Inline code that deletes a file
   (`os.remove`, `Path.unlink`, `shutil.rmtree`, `fs.rmSync`, PHP's `unlink`) now
   counts as a write in the inline-code scan, as `open(…, "w")` does, so
   `python3 -c 'os.remove("/etc/passwd")'` is held too. `/var` is left out: it holds
   programs' data, logs and macOS's per-user temporary folders. Reads are unchanged. A project
   under `/usr/src` keeps `project-fs`'s allow, which is tried before review. This
   also settles finding 8's download.
3. **`persistence`** extends: the system's cron spools and tables, `/etc/periodic`,
   systemd's system and user unit folders, SysV init scripts, `/Library/LaunchDaemons`
   and `/Library/LaunchAgents`; `systemctl enable` and the forms that install a unit
   for later boots, a `systemd-run --on-*` timer, `launchctl load`, `bootstrap`,
   `enable` and `submit`. Starting, stopping and listing stay as they were.
4. **One reading of a URL for every action kind.** `Action::Fetch` is read as an
   ADR-047 page open (`engine/atoms/urls.rs`, the same function the browser path
   uses): a domain name is a `fetch`, and an IP address in any spelling the URL
   parsers accept, a single-label name or a URL with a user part is `net` as well, so
   `default.net`, `cloud-metadata` and `local-net` decide it as they decide `curl`.
   The host stays a `fetch` atom beside it, so a `fetch` rule that named it still
   applies (strictest wins). The web URLs inside a URL are hosts for a fetch tool and
   for a `curl`/`wget` word alike (`host::web::embedded_hosts`, one function). Loopback
   written plainly (`localhost`, `127.0.0.1`, `[::1]`) stays `local-net` (defer), as for
   `curl`: dev servers are an everyday target and the policy defers them on purpose.
   Other loopback spellings (`127.1`, `0x7f000001`) were already denied for `curl` and
   now are for a fetch tool; a dev tool has no reason to write them.
5. **Credentials without a prefix.** GitLab's other token prefixes join the shape list
   (and the audit log's, which must find the same tokens). A new module,
   `token/credentials.rs`, finds kinds that need context and stay out of that list
   (the push check uses it, and sample JWTs are common in test data): an AWS secret
   access key as the value of a name ending in `secret_access_key` and a PEM
   private-key header give `@token-egress` (deny), with AWS's hosts and no host as
   owners; a JWT (three base64url parts, two of them `eyJ`) and a database URL with a
   literal password give `@credential-egress`, which the new review rule
   `credential-egress` names. A JWT and a database URL are often sent to the service
   they are for, which the JWT's shape does not name, so they are held for review, and
   the atom counts only where a rule names it, as `@pii-egress` does (ADR-052), so a
   policy made from an older default decides as before. Loopback hosts are left out.
   Crypto seed phrases and raw private keys are not added: a deterministic BIP-39
   check needs its 2048-word list and a SHA-256 checksum the core does not have, and
   without the checksum twelve common English words are a phrase; a 64-hex-digit key
   is indistinguishable from a hash.
6. **`stops-system`** (review) names `@kills-system <what>` atoms from
   `shell/kills.rs`: a `pkill`/`killall` pattern one of whose alternatives could match
   a system process's name itself or names it by path, every process of `root`,
   `kill 1`, `kill -9 -1`, and `kill` of the pids `pgrep` or `pidof` looks up for such a
   name. The narrower reading (not `stops-openmoat`'s "the pattern holds the name") keeps
   `pkill -f initdb` and `pkill -f "node server"` quiet. `kill <pid>` is untouched.
7. `curl $url`, whose host is known only at run time, stays `defer`: a `GET` sends
   nothing but the URL, like a fetch tool's read of an unlisted URL, and `curl
   "$API_URL/health"` is common in scripts. A request that also sends a body to such a
   host is already `request-rule` (review).

## Future work (not in the default policy)

**Encoded tokens in URLs without taint (finding 6).** Signals: in a `fetch` or `curl`
URL's path, query and fragment, decode each run of 16 or more base64, base64url or hex
characters once, and percent-decoding up to the three rounds `host::web` already
applies, then run the token shapes and `token/credentials.rs` on the result; a match is
`@token-egress` with the decoded kind. Benign corpus needed first: signed URLs (S3,
GCS, CloudFront `Signature=`), OAuth `state` and `code` values, pagination cursors,
analytics ids, data URLs, base64 image thumbnails in query strings, and the base64
segments of JWTs the agent's own API returns. Risk: a decoded blob that by chance
holds a prefix (`ghp_` inside random bytes is rare but `sk-` and `AKIA` are short) gives
a deny no person can explain; a decode budget (length, rounds) is needed so padding
cannot hide a token past it, and anything over the budget would need review, not
`defer`. Measure the corpus at deny and at review before choosing.

**Data in host names (finding 7).** Signals: a `fetch`, `curl` or DNS lookup whose host
has a label of 32 or more characters that is all hex, base32 (`[a-z2-7]`) or base64url,
or whose labels below the registered domain together carry more than 63 such
characters, under a domain no rule allows; `review`, never deny. Benign corpus needed
first: CDN and preview hosts (`<hash>.cloudfront.net`, Vercel and Netlify preview
deploys, `*.ngrok-free.app`, `*.trycloudflare.com`, GitHub Codespaces ports), S3
bucket names, ACME and DKIM records, tracking hosts, and `*.local` mDNS names. Risk:
preview URLs are what agents open while testing a deploy, so the rule needs an
exclusion list it would have to keep current, or a label length past what those
services issue. The proxy, which sees the DNS name actually resolved, is the better
place for a hard check.

Also not covered: a script written to a file and then run, logic-only snippets, pids a
script finds at run time (`kill -9 $pid` in a loop over `ps`), content in MCP
arguments, and calls only a session shows (BENCHMARKS.md).

## Consequences

- An agent writing to `/etc` or `/usr` on a machine where it may (a container running
  as `root`) is held for review once per call; the OS sandboxes refuse those writes
  anyway, so only hook-only setups see a change.
- `/etc` and `/etc/ssh` now hold secret paths, so the folder rule (ADR-038) holds a
  read of either folder itself for review (`protected-contents`): `ls /etc`, `grep -r …
  /etc`, `tar czf … /etc/ssh`, as it does for `~/.ssh`. A recursive read of them reaches
  the password hashes and host keys where the agent runs as `root`; reads of the files
  and folders below (`cat /etc/os-release`, `ls /etc/nginx`) keep their verdict.
- A fetch tool can no longer reach a private address or an unusual loopback spelling
  unasked; a team that needs one (an internal wiki at `10.0.0.5`) allows it under
  `net`.
- A JWT sent with a `curl` to an allowed host (a GitHub App's JWT to `api.github.com`)
  is held for review; allowing the `@credential-egress jwt <host>` atom for that host
  is the way out.
- `openmoat policy upgrade` brings the new rules and patterns into a policy made from
  an earlier default; until then a `@credential-egress` atom is dropped there and a
  `@kills-system` atom falls to the catch-all as the `kill` itself does, so neither
  changes a verdict, `@token-egress` for the new kinds
  denies through the existing `token-egress` rule, and the fetch-tool change applies
  to every policy, since it is how the engine reads a URL.

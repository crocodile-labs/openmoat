# Architecture decision records

Each ADR records one decision that constrains the code: context, decision,
consequences. Accepted ADRs are never edited; a later ADR supersedes, amends or
refines them. To add one, copy the shape of ADR-004 and take the next number.
The `spikes/` evidence that ADR-018 and ADR-023 cite was moved out of this repository;
each ADR records the outcome it needs.

| ADR | Decision | Status |
|---|---|---|
| [001](ADR-001-rust-for-the-kernel.md) | Rust for every kernel crate; TypeScript and Python only for userland SDKs and host plugins | accepted |
| [002](ADR-002-deny-is-absolute.md) | Evaluation is `deny → allow → ask → defaults`; allow never overrides deny; kind-wide denial is a per-kind default; strictest wins across atoms | accepted |
| [003](ADR-003-decide-and-enforce.md) | The parser is not the security boundary; OS enforcement, an egress proxy and session taint are the answer | accepted; release timing superseded by ADR-013 |
| [004](ADR-004-exit-code-contract.md) | Exit codes: 0 allow/ask/ok, 2 deny, 3 unresolved ask, 64 usage or configuration error | accepted; amended by ADR-015 |
| [005](ADR-005-own-posix-lexer.md) | An own POSIX lexer and classifier in `openmoat-core`; inline interpreter code is scanned, not parsed; anything unclear is `unparseable` (ask) | accepted |
| [006](ADR-006-policy-lock-integrity.md) | `policy.lock` pins policy, approval, environment and hook files by location, symlink-aware; drift denies everything until a person re-pins | accepted |
| [007](ADR-007-approvals-overlay.md) | `moat allow`: exact-text session grants in `approvals.json`, permanent rules in the pinned `policy.d/approved.yaml` overlay | accepted |
| [008](ADR-008-program-resolver.md) | Executable pinning through a CLI-supplied `ProgramResolver` over the search path recorded at `moat init` | accepted |
| [009](ADR-009-path-resolver.md) | Paths are checked literally and symlink-resolved through a CLI-supplied `PathResolver`; strictest wins | accepted |
| [010](ADR-010-shell-pattern-end-anchor.md) | A trailing bare `$` anchors the end of a shell pattern; the `env-dump` deny group uses it | accepted |
| [011](ADR-011-pty-wrappers-are-kernel-self.md) | `script`, `expect` and `unbuffer` around `moat allow\|doctor\|init\|policy` are denied by `kernel-self` | accepted; refines ADR-007 |
| [012](ADR-012-shell-pattern-exclusions.md) | `!` exclusions in shell pattern lists; `dev-shell` excludes options that run programs or write files | accepted |
| [013](ADR-013-alpha-decides-beta-enforces.md) | Alpha releases decide only and say so; enforcement gates beta; the benchmark gates 1.0 | accepted; supersedes the release clause of ADR-003 |
| [014](ADR-014-more-pty-wrappers-are-kernel-self.md) | More pseudo-terminal routes to `moat` (absolute `script`/`expect`, Python `pty.spawn`, `tmux`, `screen`, `osascript`) are denied | accepted; refines ADR-011 |
| [015](ADR-015-guard-usage-errors-deny.md) | `moat guard` exits 2 (deny) when it cannot parse its own arguments | accepted; amends ADR-004 |
| [016](ADR-016-stable-hook-binary-path.md) | Hooks and the lock record the stable install path of `moat`; `doctor` names a missing or different hook binary | accepted; refines ADR-006 |
| [017](ADR-017-fetch-kind.md) | `fetch`, a narrower kind of `net` for a host's own read-only fetch tool (`WebFetch`); the default asks for unlisted hosts | accepted |
| [018](ADR-018-enforcement-approach.md) | Enforcement tiers: Standard (the host's own sandbox, generated and pinned by OpenMoat), Isolated (container or VM with OpenMoat outside), Lightweight (generated Seatbelt or Landlock); Seatbelt does not nest | accepted |
| [019](ADR-019-one-policy-compiled-to-every-enforcement-point.md) | One policy compiled to every enforcement point through one IR; lossy targets narrow, never widen; differential executing tests prove the layers agree | accepted |
| [020](ADR-020-egress-proxy-and-secrets-broker.md) | `moat proxy` is the only network exit; the secrets broker injects credentials so the agent never holds them; minimal session taint | accepted |
| [021](ADR-021-os-layer-allowances.md) | An OS layer may be wider than the hook only by listed allowances: `sandbox.read_roots` and what a host needs to run, each printed by `moat sandbox show` | accepted |
| [022](ADR-022-repository-policy-and-trust.md) | `<project>/.moat/policy.yaml` adds deny and ask rules by itself; its allow rules apply only after `moat trust` pins that exact file by hash; hook only | accepted |
| [023](ADR-023-isolated-tier-macos.md) | Isolated tier on macOS: a Linux guest booted through Apple's `containerization` toolchain; virtiofs mounts and vsock proxy relay; bubblewrap, Landlock and seccomp nest inside, as on Linux | accepted; refines ADR-018 for macOS; a note (2026-10-12) corrects its facts about Apple's `container` and leaves open questions |
| [024](ADR-024-yaml-parser.md) | Policies are parsed by `serde-saphyr` (pure Rust, no `unsafe`) behind `openmoat_core::yaml`, kept strict: YAML 1.2 booleans only, duplicate keys, merge keys and unknown tags rejected | accepted |
| [025](ADR-025-quiet-by-default.md) | Quiet by default: a `defer` verdict leaves calls no rule names to the agent's own permission prompt; OpenMoat asks only where the effect outlives the sandbox or the session; words that only look like hosts are not network evidence | accepted |
| [026](ADR-026-mcp-server-and-tool-pinning.md) | MCP server definitions are pinned per server in the lock; a changed or new one has its tool calls denied until `moat mcp accept`; an opt-in `moat mcp proxy` pins tool descriptions and can confine the server under `moat run` | accepted; implements #133, deferred by ADR-013 |
| [027](ADR-027-per-session-proxy-credentials.md) | Per-session proxy credentials: `moat run`'s proxy serves its session alone (`Proxy-Authorization: Basic`), records each row under it, refuses hosts other than a secret's own after the session read secret material, and caps each session at half the connections; the standalone `moat proxy` stays open for the host sandboxes | accepted; refines ADR-020 |
| [028](ADR-028-hook-decisions-inside-moat-run.md) | Hooks inside `moat run` send their payload with a per-run token over the proxy's port; the `moat run` process decides with its own access (lock, policy, taint, audit row), so the sandbox stays closed to `~/.moat`; any failure denies | accepted; refines ADR-018 and ADR-027 |
| [029](ADR-029-file-provenance-taint.md) | Session taint follows written files: a write by a tainted session is recorded by path (and `Write`'s content hash) in an append-only audit table; a later session that reads or runs the file while it still holds that content is tainted; a clean `Write` clears it; `taint: { provenance: false }` turns it off | accepted; refines ADR-020 |
| [030](ADR-030-package-install-checks.md) | Package installs are read for the names they fetch; a name close to one on a bundled offline list of popular packages asks (`package-near-miss`); `moat run` sets npm's and uv's release-age settings (`sandbox.package_min_release_age_days`, 7 days) | accepted; refines ADR-025 |
| [031](ADR-031-audit-anchors-and-signed-policy.md) | `moat audit anchor` records the log's head in a git ref or file the person names, and `moat audit verify --against` checks the log against it, with nothing sent anywhere; policy packs and, where the policy asks, repository policies are trusted by OpenSSH signatures (`ssh-keygen -Y`, namespace `openmoat-policy`) from keys `moat policy trust-key` pinned; `kernel-self` also denies reading the state beside the policy | accepted; implements the signed packs of #136; amended by ADR-036 (packs signed in `openmoat-pack`) |
| [032](ADR-032-mcp-proxy-holds-first-sight.md) | `moat mcp proxy` holds every tool of a server it has no pins for until a person runs `moat mcp accept`; existing pins stay; `mcp: { trust_first_sight: true }` restores pinning on first sight, and `moat policy lint` warns about it | accepted; supersedes the first-sight part of ADR-026 |
| [033](ADR-033-openclaw-plugin-hook.md) | OpenClaw is supported through a dependency-free plugin whose `before_tool_call` handler runs `moat guard --host openclaw` and blocks on any failure; `moat init` installs and pins it and its `openclaw.json` entries; an ask is OpenClaw's own approval request | accepted |
| [034](ADR-034-hook-only-deny-groups.md) | A `deny` group with `hook_only: true` is applied by the hook and left out of every OS layer, listed under `decide-only`; the default `build-credentials` denies the agent Maven and Gradle settings while `mvn` and `gradle` still read them in the sandboxes | accepted; refines ADR-019 and ADR-021 |
| [035](ADR-035-bodyless-curl-is-a-fetch.md) | A `curl` or `wget` command that provably sends nothing but its URLs (an allowlist of options, no expansions, a domain-name host) is a `fetch` of each host, decided like `WebFetch`; anything else stays `net` | accepted; refines ADR-017; amended 2026-10-20 (`-q`/`--no-config --no-netrc` required, every written file checked, `-w` and server-chosen names stay `net`) |
| [036](ADR-036-pack-signature-namespace.md) | Policy packs are signed and verified in the namespace `openmoat-pack`, repository policies in `openmoat-policy`, so a signed pack is never a signed repository policy or the reverse; `trust-key` allows both | accepted; amends ADR-031; amended by ADR-037 (repository policies signed in `openmoat-repo-policy`) |
| [037](ADR-037-repo-policy-signature-namespace.md) | Repository policies are signed and verified in `openmoat-repo-policy`; nothing verifies in `openmoat-policy`, which earlier releases used for packs too, so an old pack's signature is no repository policy signature | accepted; amends ADR-036 |
| [038](ADR-038-folders-holding-denied-paths-ask.md) | Reading a folder that is or holds the literal folder of a deny rule's `fs.read` pattern, or writing into one that holds a deny rule's `fs.write` folder, asks (`protected-contents`); extractions (`tar -x -C`, `unzip -d`) and `git checkout` pathspecs are writes | accepted; refines ADR-002 and ADR-013 |
| [039](ADR-039-session-written-code.md) | Running a file the same host session wrote (`python3 x.py`, `bash x.sh`, `./x`) asks (`session-written-code`) where no OS sandbox from OpenMoat holds the command (hook-only agents, native Windows, a sandbox not in place); every session's writes are recorded, bounded; inline code that builds the names it opens asks (`opaque-code`) | accepted; refines ADR-013, ADR-018 and ADR-029 |
| [040](ADR-040-opencode-2-plugin.md) | OpenCode 1 (1.3.4 and later) and 2 through one plugin exporting `{ id, server, setup }`; on OpenCode 2 the plugin replaces the event's `tool` and `input` with the checked name and a frozen copy that cannot be reassigned, pins the checked shell command, and puts an `ask` to the person through OpenCode's permission prompt; a configuration's `-openmoat` is reported, and the files and variables that add or move configuration are `kernel-self`'s | accepted; builds on ADR-033 |

## Names in older ADRs

ADRs written before 2026-10-07 call the product "moat" or "agentmoat" and its crates
`moat-*` in `crates/moat-*`. Today the product is OpenMoat, its crates are
`openmoat-*` in `crates/openmoat-*`, and the command is still `moat`.

## References to retired documents

Older ADRs cite documents that were folded into the current set. Read them as:

| Cited as | Now |
|---|---|
| `DESIGN.md` §3 (threat model, T1–T12), §9 (G1–G12) | [THREAT_MODEL.md](../THREAT_MODEL.md) |
| `DESIGN.md` §4–5, §7 (hooks, components, pipeline, paths) | [ARCHITECTURE.md](../ARCHITECTURE.md) |
| `DESIGN.md` §6 (policy semantics) | [POLICY.md](../POLICY.md) |
| `DESIGN.md` §8.3–8.4 (own approval prompt, Telegram) | not built, and no issue |
| `STRENGTH.md` §3.3 (benchmark gate), `PROGRESS.md` §4 | [ROADMAP.md](../ROADMAP.md) and issue #144 |
| `STRENGTH.md` W6 (prompt fatigue), §4.1 (fuzzing, differential testing) | [THREAT_MODEL.md](../THREAT_MODEL.md) §5–6 |
| `TECH_STACK.md` | ADR-001 (the full scored comparison is in git history) |

Some ADR consequences describe gaps that later work closed: ADR-008's note that
`moat policy check` has no environment snapshot and that Windows ignores `PATHEXT`,
and ADR-017's note that no default `net` deny covers link-local addresses (the
`cloud-metadata` group does now). [POLICY.md](../POLICY.md) describes current
behaviour.

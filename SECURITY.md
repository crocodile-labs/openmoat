# Security policy

OpenMoat is a security control. Reports about it are handled as such.

**The operating system enforces only part of the policy** (ADR-013, ADR-018).
OpenMoat decides whether each agent tool call its hook reports may run, and records it.
The operating system confines only the commands inside the host sandboxes `openmoat init`
configures (Claude Code `Bash`, `PowerShell` and `Monitor`; every Codex command; the
terminal commands Cursor runs in its sandbox) and agents started with `openmoat run`.
Everywhere else an allowed call runs with your permissions and the policy decision is
the only check, so a classifier mistake that lets a dangerous action through is a
vulnerability, not a usability bug.

## Supported versions

| Version | Security fixes |
|---|---|
| the latest minor release (the newest `0.x.y`) | yes, in its next release |
| older minor releases | no; upgrade to the latest minor |
| pre-releases (`-rc.N`) | no; upgrade to the release they led to |
| `main` | yes, fixes land here first |

Before 1.0 only the latest minor release line gets security fixes, and there are no
backports to older minors.

How a fix ships:

- It lands on `main` first, with an attack fixture in `tests/conformance/` that shows
  the bypass is closed, and a `### Security` line in [CHANGELOG.md](CHANGELOG.md).
- It goes out in the next release, from GitHub Releases, the Homebrew tap and crates.io,
  with a GitHub Security Advisory for a confirmed issue in a released version
  ([What happens next](#what-happens-next)).
- A fix in the default policy reaches an existing `policy.yaml` only through
  `openmoat policy upgrade`, because an upgrade keeps your policy as it is. The CHANGELOG
  line says "Existing policies get it with `openmoat policy upgrade`" when that applies.
- After upgrading, run `openmoat doctor` and `openmoat policy upgrade`
  ([docs/INSTALL.md](docs/INSTALL.md#upgrading) says what each one may ask for).

## Reporting

Use GitHub's private advisory form:
[report a vulnerability](https://github.com/crocodile-labs/openmoat/security/advisories/new).
Only the maintainers see it.

Do not open public issues or pull requests for bypasses. Looking for one on purpose? The
[Break OpenMoat](docs/CHALLENGE.md) challenge gives a ready target and says how valid
reports are credited. A useful report contains:

- the `openmoat --version` or commit, the host and the operating system
  (`openmoat doctor --bundle moat-bundle.json` writes these, and the agents' hook state, to
  one local file you can attach after reading it);
- the exact tool call: the hook payload, or the command line for `openmoat policy check`;
- the policy in use (default, or the file) and the verdict and rule ids you got;
- what actually executes and why that crosses a boundary the policy promises.

A report is accepted when it shows a concrete crossing of the boundaries in the table
below. Scanner or model output without a reproduction is read, but it is not triaged
ahead of reports that have one.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement | 72 hours |
| Triage: confirmed or not, severity | 7 days |
| Fix for a confirmed critical or high issue | 30 days |
| Public disclosure | when the fix ships, and at most 90 days after the report unless we agree otherwise |

Every valid bypass becomes a conformance fixture before the fix is published. Confirmed
issues in a released version get a GitHub Security Advisory, with a CVE requested
through GitHub, and you are credited unless you prefer otherwise.

## Safe harbour

Research on your own machine and your own accounts, against your own copy of OpenMoat, is
welcome and will not be pursued. Do not test against systems or data that are not
yours.

## What counts as a vulnerability

| In scope | Example |
|---|---|
| Policy bypass | a command the default policy should deny is allowed, or evaluated as a different action than the one that executes |
| Parser confusion | quoting, operators, substitutions or encodings that make the classifier see something other than what the shell runs |
| Fail-open | any error path in `openmoat guard` that results in `allow` |
| Sandbox generation | a generated host sandbox setting, Seatbelt profile or Landlock rule that allows more than the policy and than `openmoat sandbox show` reports |
| Self-protection gap | an agent tool call that can modify `~/.moat`, host hook configuration or the `openmoat` binary without a `deny` |
| Audit integrity | decisions missing from the log, or secrets persisted un-redacted |
| Supply chain | malicious or vulnerable dependencies; release artefacts whose checksum or attestation does not verify |

## Out of scope (today)

These are known limits, documented in `docs/THREAT_MODEL.md` §4–5 and
`docs/ROADMAP.md`, rather than bugs:

| Not yet covered | Status |
|---|---|
| OS enforcement where no sandbox applies (Claude Code's and Cursor's file tools, `WebFetch` and MCP calls; commands Cursor runs outside its sandbox; every call of the hook-only agents OpenClaw, GitHub Copilot CLI, pi, Gemini CLI and OpenCode; native Windows): a report that an allowed call could do harm because nothing below the decision stops it (a misjudged call is a policy bypass, in scope) | `openmoat run`; Windows enforcement (#135), Isolated tier (#174, #175) |
| Sandbox gaps listed as gaps in `docs/EVIDENCE.md` or as losses by `openmoat sandbox show` (for example, on Linux `openmoat run` cannot deny `.env` inside the project) | tracked in the issue each one names |
| HTTPS secret injection, and per-host method and path rules, in `openmoat proxy` | #247 |
| Data sent to a host the policy allows (`api.github.com`, registries) by an allowed or approved command, including project scripts such as `npm test` | known limit; session taint asks for network after a secret read |
| PowerShell / cmd tokenisation | Claude Code `PowerShell` is always `unparseable`, which the default policy defers to the agent's own prompt (ADR-025); other PowerShell lines are lexed as POSIX and fall through to the catch-all default |
| Hosts that proceed when the hook binary is missing or killed, or when the hook times out (GitHub Copilot CLI, Gemini CLI) | host limitation; `openmoat status` reports a missing hook |
| Tools no hook reports (Codex web search and other hosted tools, the shell commands a person types in OpenCode with `!`) | host limitation: the hook never sees them |
| Agents that run calls unchecked when they do not load OpenMoat's plugin or extension (OpenCode with `--pure` or `OPENCODE_PURE`, or a plugin that fails to load; OpenClaw; pi), and other plugins or extensions in the agent's own process changing what OpenMoat's does (OpenCode, pi, OpenClaw) | host limitation; an agent starting OpenCode without plugins, or writing OpenMoat's plugin and the files that load plugins, is denied (in scope if it is not) |
| OpenCode 2 (`@opencode/cli`), whose plugin API OpenMoat does not support yet | not supported; `openmoat init` does not set it up (#265) |

| An attacker with root or the user's own shell, a compromised release pipeline, prompt-injection detection in text | not a target (THREAT_MODEL §4) |
| Agents running in a vendor's cloud rather than on the host | not a target |

## Threat model in one paragraph

The attacker controls any text the agent reads (files, issues, web pages, MCP tool
descriptions, dependencies) and may publish packages and MCP servers. The attacker
does not have root on the machine. The kernel's job is to keep such an attacker
from reading secrets, exfiltrating data, poisoning the environment, running remote
code, destroying work, or disabling the kernel, and to leave a trustworthy record of
every attempt. Full version: `docs/THREAT_MODEL.md`.

## Verifying a release

Every release carries SHA-256 checksums (`sha256.sum`) and GitHub build provenance
attestations. Verify a downloaded artefact with
`gh attestation verify <file> --repo crocodile-labs/openmoat`
before installing it by hand.

## Hardening already in place

Deterministic decisions (no model in the loop); a policy lock verified on every call
(edits to the policy or hook files deny everything until a person re-pins); fail-closed
on every error path in `openmoat guard`; exit code 2 reserved for `deny`; protected paths
for the kernel's own configuration; redaction before audit storage; owner-only permissions on state files; a pure core
with no I/O and no `unsafe`; dependency and licence auditing in CI.

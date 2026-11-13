# Compliance evidence

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you need records of what your agents were allowed and denied for a security review or audit.

Evidence, not a certification. `openmoat audit evidence` turns the audit log into a report
a security reviewer or auditor can read: for a time window, per control of three public
frameworks, which OpenMoat rules fired, how often by verdict, and sample events. It does
not show that a control is met, and using OpenMoat does not make anyone compliant. It
gives you records to show when someone asks how you control what your coding agent does.

The frameworks:

- OWASP Top 10 for LLM Applications 2025 (`LLM01:2025` … `LLM10:2025`)
- SOC 2 Trust Services Criteria, common criteria CC6 to CC8
- ISO/IEC 27001:2022 Annex A

## Make a report

```bash
openmoat audit evidence --since 2026-10-01 --until 2026-11-01 > evidence-october.md
openmoat audit evidence --since 30d --format json > evidence.json
openmoat audit evidence --since 7d --host claude-code --samples 5
```

| Option | Meaning |
|---|---|
| `--since` | window start: `all` (default), `today`, `yesterday`, `12h`, `7d`, `2w` or `YYYY-MM-DD` (UTC) |
| `--until` | window end, not included, in the same forms (`2026-11-01` ends before that day); default now |
| `--host` | only one agent's events |
| `--samples` | sample events per rule group and control, 0 to 50 (default 3) |
| `--format` | `text` (Markdown, the default) or `json` (format `openmoat-evidence-v1`) |

Run it from your own terminal: an agent's sandbox cannot read the audit log. Nothing is
sent anywhere.

## What the report holds

- **The statement** that this is evidence, not a certification, in both formats.
- **Decisions in the window**, by verdict.
- **The audit log**: whether the whole hash chain verifies, its head, and the window's
  first and last event ids and the newest event's hash. To show a reviewer the events
  were not changed, give them an export with that hash:

  ```bash
  openmoat audit export --since 2026-10-01 > window.jsonl
  openmoat audit verify window.jsonl --anchor <the hash from the report>
  ```

- **The policy, lock and protections at the time of the report**: the policy file's
  SHA-256 and whether it is the default policy this build ships; the lock's pinned files,
  any drift and when it was last pinned (flagged when that is after the window started);
  each agent's protection level (`hook + OS sandbox`, `hook only`, `not protected`, `not
  set up`), as `openmoat status` reports it.
- **Controls**: per framework, each control the map covers, the rule groups that relate
  to it, and decisions by verdict. An event counts once per control, however many of its
  rules relate to it.
- **Rule groups**: what the rules do, each rule's counts, whether the policy in force has
  it (a default rule you removed shows as "cannot fire"; rules the code adds itself show
  as "built in"), and sample events.
- **Rules that map to no control**: allow rules, the catch-all, your own rules and
  audit-only rows, so every decision in the window is accounted for.

Sample events are the stored rows, which were redacted before they were written (the same
redaction as `openmoat audit export`). Recorded text is shown with control characters
replaced, so a command cannot change your terminal or the Markdown layout.

## Example output

Shortened, for a log of six decisions (the unit tests' fixture; hashes cut):

```markdown
# OpenMoat evidence report

Evidence, not a certification. This report lists what OpenMoat recorded about an agent's tool calls on this machine and which framework controls those records relate to. It does not show that any control is met, and using OpenMoat does not make anyone compliant.

- Window: 2026-10-01T00:00:00Z to 2026-11-01T00:00:00Z (UTC, end not included)
- Generated: 2026-11-04T09:12:40Z
- Decisions: 6 (allow 1 · defer 1 · review 1 · deny 3)

## Audit log

- Hash chain: intact over 6 events, head `3f1c…`
- This window: events 1 to 6; the newest has hash `3f1c…`. …

## Controls

### OWASP Top 10 for LLM Applications 2025

| Control | Rule groups | Decisions | allow | defer | review | deny |
|---|---|---|---|---|---|---|
| LLM02:2025 Sensitive Information Disclosure | secrets, secret-egress | 2 | 0 | 0 | 0 | 2 |
| LLM03:2025 Supply Chain | packages, mcp | 1 | 0 | 0 | 1 | 0 |
…

## Rule groups

### Secrets and credentials (`secrets`)

The rules deny or hold for review the agent's reads of key files, credential stores, secret environment variables and folders that hold them. Controls: LLM02:2025, CC6.1, A.5.17, A.8.3.

| Rule | In the policy | allow | defer | review | deny |
|---|---|---|---|---|---|
| `secrets-paths` | yes | 0 | 0 | 0 | 2 |
…

Samples (newest first, the strictest verdicts before the rest; stored redacted):

- event 3 · 2026-10-03T00:00:00Z · claude-code · deny [token-egress, secrets-paths] `curl -H 'Authorization: Bearer [redacted]' https://x.test`
```

## The map

The map is data in the code (`crates/openmoat-cli/src/compliance.rs`), tested against the
default policy: every `deny` and `review` rule of the default policy is in exactly one group,
no `allow` rule is in any, and every other rule id is one the code adds itself
([POLICY.md](POLICY.md) §5.1). A control is listed only where the rule's decisions are
records of that control operating on an agent's tool calls.

| Rule group | Rules | OWASP LLM 2025 | SOC 2 | ISO/IEC 27001:2022 |
|---|---|---|---|---|
| `secrets` | `secrets-paths`, `build-credentials`, `kerberos-tickets`, `agent-credentials`, `env-secrets`, `env-dump`, `home-sweep`, `other-home`, `secret-names`, `docker-secrets`, `agent-token`, `protected-contents` | LLM02 | CC6.1 | A.5.17, A.8.3 |
| `secret-egress` | `token-egress`, `placeholder-egress`, `encoded-egress`, `card-egress`, `session-taint`, `push-secret`, `proxy-secret`, `proxy-secret-route`, `proxy-tls` | LLM02 | CC6.7 | A.5.14, A.8.12 |
| `network` | `default.net`, `cloud-metadata`, `proxy-address`, `proxy-sni`, `proxy-request`, `proxy-upstream`, `proxy-port`, `proxy-session` | | CC6.6 | A.8.23 |
| `code-execution` | `pipe-to-shell`, `opaque-code`, `session-written-code`, `executables`, `container-host`, `wsl-crossing` | LLM05 | CC6.8 | A.8.7 |
| `packages` | `package-near-miss` | LLM03 | CC6.8 | A.8.19 |
| `runs-later` | `runs-later`, `persistence`, `shell-rc`, `git-internals`, `env-poison`, `push-runs-later` | | CC6.8 | A.8.7 |
| `self-protection` | `kernel-self`, `agent-folders`, `managed-settings`, `stops-openmoat`, `provenance-notes` | LLM06 | CC8.1 | A.8.9 |
| `integrity` | `kernel-integrity`, `settings-drift`, `project-settings` | | CC7.1, CC8.1 | A.8.9 |
| `mcp` | `mcp-server-changed`, `mcp-tool-held`, `mcp-unattributed` | LLM03 | CC6.8, CC7.1 | A.8.19 |
| `destructive` | `destructive`, `destructive-recoverable` | LLM06 | | |
| `audit-log` | every recorded event | | CC7.2 | A.8.15 |

Not mapped, on purpose: LLM01 Prompt Injection (OpenMoat limits what an injected
instruction can make the agent do, which is LLM06, but does not detect injection), LLM04,
LLM07, LLM08, LLM09 and LLM10, and every SOC 2 or ISO control about people, processes or
systems other than the agent's tool calls. Control titles in the report are short
paraphrases; the frameworks' own texts are the reference. The decision is
[ADR-051](adr/ADR-051-compliance-evidence.md).

## Limits

- **State, not history.** The policy, lock and protections are read when you run the
  report. The audit log does not record which policy decided each call; when the lock
  was re-pinned after the window started, the report says the policy in force during the
  window may differ.
- **Only what reached OpenMoat.** An agent that is not set up, a hook that failed open, a
  tool outside the hook or a command inside an allowed script is not in the log
  ([THREAT_MODEL.md](THREAT_MODEL.md) §5). Zero denies can mean nothing was attempted or
  that nothing was checked; the protections table tells you which agents were checked.
- **Counts are not effectiveness.** A rule that fired shows the rule operated on that
  call; no number in the report says a control is designed or operating effectively.
- **By rule id.** The map follows rule ids. A custom policy that keeps an id but changes
  its patterns keeps its mapping; the report shows whether the policy is the shipped
  default.
- **One machine.** For several machines, export each log and combine them with
  `openmoat audit report`, which does not map controls.
- **A project's repository policy** (`.moat/policy.yaml`) is not shown; its rules appear as
  `repo:<id>` under rules that map to no control.

# Audit delivery to a SIEM

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want every OpenMoat decision on this machine in your SIEM or log collector as it happens, not only when someone runs `openmoat audit export`.

**On this page:** [How it works](#how-it-works) · [Set it up](#set-it-up) · [The configuration](#the-configuration) · [What is sent](#what-is-sent) · [Check it](#check-it) · [Collectors](#collectors) · [When a sink fails](#when-a-sink-fails) · [Limits](#limits)

OpenMoat can send each decision to up to four places ("sinks"): an OpenTelemetry
(OTLP/HTTP) logs endpoint, or an HTTPS webhook whose bodies it signs. Delivery never
slows or changes a decision, everything is masked before it leaves, and a sink that
cannot keep up is told exactly what it missed. The design is
[ADR-081](adr/ADR-081-live-audit-delivery.md).

## How it works

- The audit log is the queue. Each sink keeps its place in the log
  (`~/.moat/delivery/<sink>.json`); nothing is copied anywhere else on disk.
- `openmoat guard` sends nothing. After it has answered the agent it starts
  `openmoat audit deliver flush --background` in the background, if no run is going and
  a sink is due. That run sends the events after each sink's place, in batches.
- A sink that is down is tried again later, waiting longer each time (5 s doubling to
  15 min). A sink that answers with an error trying again cannot fix (`401`, `404`, …)
  is paused until you run `openmoat audit deliver flush`.
- A sink more than `max_backlog` events behind skips the oldest. The skip is recorded in
  the audit log as its own event (rule `audit-delivery-overflow`) and sent to the sink
  with its next request. The skipped events stay in the local log.

## Set it up

1. Put the key or token the sink needs in a file inside `~/.moat/delivery/`, readable
   by you only (the agent can neither read nor change files there):

   ```bash
   mkdir -p ~/.moat/delivery
   openssl rand -hex 32 > ~/.moat/delivery/webhook.key
   chmod 600 ~/.moat/delivery/webhook.key
   ```

2. Write `~/.moat/delivery.yaml` (below).
3. Accept it from your terminal. Until you do, every agent call is denied: the file
   decides where your audit log goes, so the policy lock pins it as it pins the policy.

   ```bash
   openmoat doctor --accept
   ```

4. Check it:

   ```bash
   openmoat audit deliver test
   openmoat audit deliver status
   ```

Any later change to `delivery.yaml` stops every call again until you run
`openmoat doctor --accept`.

## The configuration

```yaml
version: 1
machine: alice-laptop      # host.name in OTLP, "machine" in webhook bodies
start: new                 # new (default): from when you accepted the file; all: the whole log
max_backlog: 100000        # how far a sink may fall behind (100 to 10000000)
batch_bytes: 524288        # the most bytes of events per request (4 KiB to 8 MiB)
sinks:
  - id: collector                              # 1-32 of a-z, 0-9, -
    otlp: https://otel.example.com:4318/v1/logs
    headers:                                   # optional
      - name: Authorization
        prefix: "Bearer "
        value: { file: ~/.moat/delivery/collector.token }
    ca_file: ~/.moat/delivery/internal-ca.pem  # optional; else the system's roots
  - id: siem
    webhook: https://siem.example.com/openmoat
    secret: { file: ~/.moat/delivery/webhook.key }   # required for a webhook
```

- `otlp:` takes `https://`, or `http://` to `localhost`, `127.0.0.1` or `[::1]` only (a
  collector on this machine). `webhook:` takes `https://` only.
- A value (`secret:`, a header's `value:`) is `{ file: <path> }` inside the state
  directory's `delivery/` (the agent can read some other files of the state directory,
  never this one) or `{ keychain: { service: …, account: … } }`. `{ env: … }` is refused: the
  background run starts from the agent's hook, in the agent host's environment.
- `ca_file:` must be inside the state directory too.
- Addresses that are link-local, cloud metadata or not unicast are refused whatever the
  name; private and loopback addresses are allowed. No redirect is followed and no
  `HTTPS_PROXY` is read.

## What is sent

Each event of the audit log becomes one record: its id, time, agent (`host`), session,
call id, working directory, tool, action, verdict, rules, reasons, decision time, and
its chain hash and the previous one. Every text is masked again before sending: the
patterns the audit log uses, the values of the policy's brokered secrets with a file
source, and the sink's own key and header values. After masking, a record over the
batch size or 256 KiB has its long texts cut to fit, each ending with `…[openmoat trimmed
N bytes]`; the whole event stays in `openmoat audit export`. The chain hash lets you match a SIEM
row with `openmoat audit export`; the chain itself is checked with `openmoat audit
verify` on an export, not in the SIEM.

The records still say which commands ran, which files were read and which hosts were
reached. Send them only where you would keep the audit log itself.

**OTLP** (`Content-Type: application/json`): one `ExportLogsServiceRequest` per batch,
resource `service.name: openmoat`, `service.version`, `host.name`; one log record per
event, severity `INFO` (allow, defer), `INFO2` (review), `WARN` (deny), body
`deny Bash [rule]`, attributes `openmoat.event.id`, `openmoat.host`, `session.id`,
`openmoat.tool`, `openmoat.verdict`, `openmoat.rules`, `openmoat.reasons`,
`openmoat.action` (JSON text), `openmoat.latency_us`, `openmoat.cwd`,
`openmoat.call_id`, `openmoat.hash`, `openmoat.prev_hash`. A skip is an `ERROR` record
with `openmoat.gap.first`, `.last` and `.count`.

**Webhook** (`Content-Type: application/json`):

```json
{"format": "openmoat-delivery-v1", "machine": "alice-laptop", "version": "0.19.0",
 "sent_ms": 1762790400000,
 "events": [{"id": "1f", "ts_ms": 1762790399120, "host": "claude-code",
             "session_id": "…", "call_id": "…", "cwd": "/home/alice/proj",
             "tool": "Bash", "action": {"shell": {"command": "git status"}},
             "verdict": "allow", "rules": ["dev-shell"], "reasons": ["…"],
             "latency_us": 950, "hash": "…", "prev_hash": "…"}],
 "gaps": []}
```

with these headers:

| Header | Value |
|---|---|
| `X-OpenMoat-Timestamp` | the time the request was made, ms since the epoch |
| `X-OpenMoat-Signature` | `v1=` and the hex HMAC-SHA-256, under the key, of `<timestamp>.<body>` |
| `X-OpenMoat-Delivery` | `<sink>-<first id>-<last id>`: drop a batch you already stored |

Check a body as a receiver, for example in Python:

```python
import hmac, hashlib
def valid(key: bytes, timestamp: str, body: bytes, signature: str) -> bool:
    mac = hmac.new(key, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("v1=" + mac, signature)
```

Refuse a timestamp far from your own clock to refuse a replayed body. A gap in a webhook
body is `{"first": "1", "last": "a0", "count": 160, "reason": "backlog_full"}`.

## Check it

```console
$ openmoat audit deliver test
✔ collector: accepted
✔ siem: accepted
$ openmoat audit deliver status
✔ collector (otlp) → https://otel.example.com:4318/v1/logs
   1204 delivered, 0 behind, 0 skipped (backlog full or too large)
   last accepted 2026-11-10 14:02:11 UTC
```

`test` sends one record marked `audit-delivery-test` (host `audit-delivery`), not an
agent's call, and moves no sink's place. `flush` delivers now, and resumes a paused
sink. All three take `--format json`; a failed test, a stopped flush and a configuration
that is not honoured exit 64.

## Collectors

What the tests show: OpenMoat's own tests run a local HTTP server as an OTLP endpoint
and a local HTTPS server (with its own CA in `ca_file`) as a webhook, and check the
body, the signature, a retry after a `503`, a pause after a `401`, and the gap after a
full backlog. No vendor's service and no OpenTelemetry Collector build is run by those
tests. The examples below follow the vendors' documented OTLP intake; run `openmoat
audit deliver test` against yours before you rely on it.

**OpenTelemetry Collector on this machine** (the simplest start, and the way to reach
any vendor the Collector exports to):

```yaml
# otelcol config
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318
exporters:
  debug: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
```

```yaml
# ~/.moat/delivery.yaml
version: 1
machine: alice-laptop
sinks:
  - id: otelcol
    otlp: http://127.0.0.1:4318/v1/logs
```

Replace `debug` with your vendor's exporter (Splunk HEC, Datadog, Elasticsearch, …) as
the Collector's documentation describes; OpenMoat then needs no vendor key at all.

**Splunk, Datadog, Elastic directly.** Each documents an OTLP/HTTP logs intake with its
own URL and authentication header. Put the URL in `otlp:` and the header under
`headers:`, with the token in a file inside `~/.moat/delivery/`. OpenMoat sends JSON-encoded OTLP;
an intake that accepts protobuf only will refuse it (OpenMoat pauses the sink and
`status` shows the answer).

**A webhook receiver of your own**, or a SIEM's generic HTTP input: use `webhook:` and
check the signature as above.

## When a sink fails

| What happened | What OpenMoat does | `status` shows |
|---|---|---|
| network error, TLS error, `408`, `429`, `5xx` (not `501`, `505`) | waits 5 s, doubling to 15 min, or the `Retry-After` it got (up to 1 h), then sends the same events again | `✗`, the last failure and the next try |
| `413` (request too large) | sends half as many events per request; one event alone that still gets `413` is skipped, recorded as `audit-delivery-too-large`, and sent as a gap with the next request (the sink is never paused for it) | `N skipped (backlog full or too large)` |
| an OTLP collector answers `2xx` with `partial_success` rejecting records | moves on, as the OTLP specification says such records must not be sent again; records the loss as `audit-delivery-partial` with the count and the collector's message (masked, at most 300 characters), and sends a gap spanning that request with the next one. A request of only OpenMoat's own delivery rows that is rejected again is counted but not recorded again | `N skipped (backlog full or too large)` and the collector's message as the last failure |
| any other answer (`3xx`, `400`, `401`, `403`, `404`, …), a refused address | pauses the sink; nothing more is sent to it | `paused (HTTP 401)` |
| the sink falls more than `max_backlog` events behind | skips the oldest to nine tenths of the bound, records `audit-delivery-overflow`, and sends the gap with the next request | `N skipped (backlog full or too large)` |
| `delivery.yaml` changed, or no person accepted it | every agent call is denied (`kernel-integrity`) and nothing is sent | `✗ nothing is sent: …` |

After fixing a paused sink, run `openmoat audit deliver flush`.

## Limits

- Delivery runs when an agent's hook runs or when you run `flush`. A machine where no
  agent runs sends nothing new; the egress proxy's own rows go with the next call.
- A host that ended every process its hook started, even in another process group, would
  stop a run early; the next call starts another. No host is known to; this is not
  tested with real agents.
- OTLP over protobuf or gRPC, HTTP proxies and more than four sinks are not supported.
- Values in the keychain are read by the background run as well; on macOS the first read
  may ask you to allow it, so run `openmoat audit deliver test` once from your terminal.

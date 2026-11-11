# ADR-081: Live audit delivery to a SIEM or log collector

Status: accepted · Date: 2026-11-10 · Builds on ADR-031 (anchors), ADR-043 (the proxy's TLS) and ADR-071 (the guard's state directory)

## Context

The audit log stays on the machine. `openmoat audit export` writes it as JSON Lines when
a person runs it, and a team that wants decisions in its SIEM has to schedule that
itself, with no record of what was missed. Live delivery has to meet four constraints
that the rest of OpenMoat already sets:

1. The hook decision must not wait for, or fail because of, a network request. The
   guard runs once per call and exits (ARCHITECTURE §2); there is no daemon.
2. Nothing leaves the machine unredacted (invariant 6).
3. Where the log goes is itself sensitive: a configuration an agent could write would
   send it the whole log.
4. Nothing may be dropped unseen: a collector that is down for a day, or a backlog
   that has to be cut, must leave a record.

## Decision 1: the audit log is the queue

Each sink keeps a cursor, the id of the last event it accepted, in
`~/.moat/delivery/<sink>.json`, with its failure count, its next try, why it is paused
and the gaps it has not yet been told about. A run reads the chained events after the
cursor (`Store::export_after`), oldest first, in batches of at most 500 events and
`batch_bytes` (default 512 KiB; one larger event goes alone).

No second copy of events is written. The log is already durable, append-only, hash
chained, redacted and owner-only (`0600`); a separate spool would put a second copy of
the same sensitive text on disk and add a write to the guard's path. The bound is on
how far a sink may fall behind: `max_backlog` events (default 100 000, between 100 and
10 000 000).

## Decision 2: overflow is recorded, twice

When a sink is more than `max_backlog` events behind, the run skips the oldest down to
nine tenths of the bound (room for the events that arrive while it catches up and for
the row below), then:

- records an audit event, host `audit-delivery`, session the sink id, tool `deliver`,
  verdict `defer` (it decides no call), rule `audit-delivery-overflow`, whose reason
  names the ids and the count;
- keeps the gap in the sink's state and sends it with the next request whatever that
  request carries: a `gaps` entry in a webhook body, an `ERROR` log record in OTLP.
  The gap is cleared only when the sink accepts a request that carried it.

The skipped events stay in the local log and in `openmoat audit export`. The overflow
row is itself an event after the cursor, so it is delivered too.

## Decision 3: never on the decision's path

`openmoat guard` sends nothing. After it has written its answer, and only when
`~/.moat/delivery.yaml` exists, it starts `openmoat audit deliver flush --background`
detached (`delivery::kick`): standard streams to null (a host waits for the hook's
streams to close), its own process group (`setpgid` on Unix, `DETACHED_PROCESS |
CREATE_NEW_PROCESS_GROUP` on Windows), and a cleared environment that keeps only
`HOME`, `USERPROFILE`, `SystemRoot`, `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR`
plus `MOAT_HOME` set to the guard's own state directory. `SSL_CERT_FILE` and the
proxy variables are not passed: they would choose the roots the run trusts or route
it elsewhere. It is not started when a run holds `delivery/run.lock` (one run at a
time, `File::try_lock`) or when `delivery/hold` says no sink is due before a time (all
waiting after failures or paused, or for five minutes after a run found the file not
honoured) and neither the configuration nor the lock is newer than that file.

Without a configuration the guard's added cost is one `stat`. With one, one or two
small file reads and, now and then, a process start, all after the answer is out.
Whether the spawn fails or the run fails, the decision is the same; the events wait in
the log. A run that ends lets the lock go and then checks once more for events a guard
recorded while it held the lock, so none waits for the next call. Inside `openmoat
run`'s sandbox the guard relays and returns before this point; the guard the run starts
outside (`--relayed`) records and starts the delivery.

A person runs `openmoat audit deliver flush` to deliver now, which also resumes a paused
sink, `status` to see each sink, and `test` to send one record marked as a test
(`audit-delivery-test`, id `0`, no chain hash) without moving any cursor.

## Decision 4: the configuration only a person makes take effect

`~/.moat/delivery.yaml` sits in the state directory, which `kernel-self` keeps from the
agent, and it joins the state files every lock pins (`integrity::state_files`): a new
lock pins it, as absent when there is none. Its bytes are honoured only while they
match the lock (`Lock::pinned_digest`). So:

- a file written without a person (no pin, or a pin of its absence) is drift: every hook
  call is denied with `kernel-integrity` until a person accepts it, and a run sends
  nothing;
- a person writes the file and runs `openmoat doctor --accept` from their terminal.

A lock written before this release has no entry for the file. A file created then is
not drift for the guard, but delivery refuses it until a re-pin covers it, so nothing
is ever sent from a file no person accepted.

Every value a sink reads (the webhook's HMAC key, a header's token, a CA) comes from a
file inside the state directory or from the keychain. `env:` sources are refused: the
background run inherits the agent host's environment.

## Decision 5: what goes on the wire

Each event becomes a record with the export's fields (id, time, host, session, call,
working directory, tool, action, verdict, rules, reasons, latency, chain hash and
previous hash). Every text the agent can influence is masked again before sending
(`openmoat_audit::delivery::Delivered::of`): today's patterns, the values of the
policy's brokered secrets that have a file source (as the guard masks them), and the
sink's own key and header values. A row an older build stored is thus masked by
today's patterns. The record keeps the chain hash so a SIEM row can be matched with an
export, but its cells are no longer the hashed ones; the chain is verified from
`openmoat audit export`, never from a collector.

Two formats:

- **OTLP/HTTP logs, JSON encoding** (`otlp:`): one `ExportLogsServiceRequest`, resource
  attributes `service.name` `openmoat`, `service.version`, `host.name` the configured
  machine name; one log record per event with `timeUnixNano`, `observedTimeUnixNano`,
  severity (`INFO` 9 for allow and defer, `INFO2` 10 for review, `WARN` 13 for deny,
  `ERROR` 17 for a gap), a one-line body (`deny Bash [rule]`) and `openmoat.*`
  attributes, `session.id` for the session. Field names, 64-bit integers as decimal
  strings and enums as numbers follow the specification's JSON Protobuf Encoding:
  <https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding>,
  <https://opentelemetry.io/docs/specs/otlp/#otlphttp>, and severity numbers
  <https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber>.
  These were written from the specification. No real collector accepted these bodies
  in this change's tests; CI checks them against a local test server, and the shape
  against the specification's field names.
- **Webhook** (`webhook:`, `https` only): `{"format": "openmoat-delivery-v1", "machine",
  "version", "sent_ms", "events", "gaps"}`, with `X-OpenMoat-Timestamp` (ms),
  `X-OpenMoat-Signature: v1=<hex HMAC-SHA-256(key, "<timestamp>.<body>")>` and
  `X-OpenMoat-Delivery: <sink>-<first id>-<last id>`. The timestamp is signed so a
  receiver can refuse a replay outside its window. The key is required.

## Decision 6: the network code lives in `openmoat-proxy`

The request (`openmoat_proxy::Poster`, `post.rs`) is one `POST` over `std::net` and
rustls with deadlines (10 s per step), with no redirect followed and only the answer's
status line and headers read (16 KiB at most). It sits in `openmoat-proxy` because that
crate already holds the only network and TLS code, its rules fit (network through
`std::net` only, no async runtime, no storage) and it reuses what is there: the
upstream TLS configuration (`tls::upstream_config`, ADR-043, the system roots or a
PEM CA the person gives) and the address checks (`decide::forbidden`, the metadata
names). Every resolved address is checked: link-local, cloud metadata and non-unicast
addresses are refused whatever the configuration says; private and loopback addresses
pass, where collectors usually live. Plain `http` is allowed only to `localhost` or a
loopback literal, and only when every address it resolves to is loopback, so a local
collector needs no certificate and nothing crosses a network in clear text.

The alternatives were weighed:

- a new crate would need its own publishing step in the release workflow for the
  `openmoat` crate to publish, for a few hundred lines;
- the CLI holds no network code today; putting a TLS client there would duplicate the
  proxy's TLS configuration and address checks;
- `openmoat-audit` keeps storage and redaction, so it builds the bodies
  (`openmoat_audit::delivery`: `pack`, `webhook_body`, `otlp_logs`) and opens no
  connection.

The CLI reads the configuration and secrets, keeps the cursors, signs, schedules and
starts the run: it is the crate that touches files, the environment and processes.

## Decision 7: failures

- A `2xx` answer moves the cursor and clears the gaps.
- `408`, `429` and every `5xx` except `501` and `505`, and a network or TLS failure,
  wait: 5 s, doubled per failure, at most 15 min, plus up to a fifth more at random so
  machines that failed together do not return together; a longer `Retry-After` in
  seconds wins, up to an hour. The OTLP specification names `429`, `502`, `503` and
  `504` as retryable; the others are common for webhooks and harmless to retry.
- `413`: each event is already trimmed, after masking, to the batch size and at most
  256 KiB of JSON (every text over one length cut, with a marker and the bytes cut), so
  a `413` halves the events per request for the rest of the run; one event alone that
  still gets it is skipped like a backlog overflow (rule `audit-delivery-too-large`, a
  gap sent with the next request), never a pause: one event must not stop delivery.
- Any other answer (a `3xx`, `400`, `401`, `403`, `404`, …) and a URL or
  address the client refuses pause the sink: trying again cannot change them. Only a
  person's `flush` resumes it. `status` shows the reason.

While a sink waits or is paused its backlog grows and Decision 2 bounds it.

## Consequences

- A SIEM sees decisions within about a hook call of their being made, for every agent
  OpenMoat guards, without a daemon.
- Writing or changing `delivery.yaml` stops every hook call until a person accepts it,
  as a changed policy does. This is the point: the file decides where the log goes.
- Delivery happens only while hook calls are made or a person runs `flush`. A machine
  where no agent runs sends nothing new, which is also when nothing new is recorded;
  the proxy's own rows wait for the next call.
- A host that kills every process the hook started, its own group excepted, would end
  the run early; the next call starts another. No host is known to do that; it is not
  tested against real agents.
- What a SIEM receives is redacted but still says which commands ran, which files were
  read and which hosts were reached. The person chooses the sink; the docs say so.
- Sinks: at most four; formats: OTLP/HTTP JSON and the webhook. OTLP over protobuf,
  gRPC and HTTP proxies are not supported.

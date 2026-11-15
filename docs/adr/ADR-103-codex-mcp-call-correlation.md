# ADR-103: Correlate Codex MCP metadata with one hook ticket

Status: proposed

## Context

Independent Codex threads can issue identical MCP arguments and reuse a JSON-RPC
request ID. ADR-069's argument-based fallback is not safe for attributed calls.
Codex 0.169.0 supplies the thread ID in tool request metadata; its agent tool
path also inserts the host call ID. A direct app-server call may omit it.

## Decision

For a Codex proxy, if either identity field is present, require both and consume
only an explicit allow ticket with the exact thread, host call ID, tool and argument digest.
An incomplete or mismatched pair never enters ADR-069's legacy matching logic.
Other hosts and Codex clients with neither field retain the existing entrypoint
contract until a managed gateway supplies independently authenticated bindings.

## Consequences

Two isolated Codex 0.169.0 sessions with a trusted native hook produced the
same call ID and arguments but distinct thread IDs. Each hook's session and
tool-use IDs matched the actual upstream frame. This establishes correlation,
not peer authentication.

The managed gateway must bind the agent and thread before consuming tickets.
Unix socket permissions only restrict the operating-system user, not the
agent session. The existing run relay credential is shared inside a sandbox;
it does not identify a particular agent client, and its hooks deliberately
do not produce MCP tickets. Do not promote either mechanism to a session
credential. This change does not authorize bare app-server requests or
qualify deployment of a shared daemon.

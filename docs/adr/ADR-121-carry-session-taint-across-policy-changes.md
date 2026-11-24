# ADR-121: Carry a session's taint forward across a policy change or an upgrade

Status: accepted · Date: 2026-11-24 · Builds on ADR-020 (session taint, its note on the
session cache, #570)

## Context

The guard keeps each session's taint fold in the audit database, keyed by a digest of
this build's version, the host, the effective policy and its context (ADR-020's note).
An upgrade or any policy change (`openmoat policy upgrade`, an edited
`.moat/policy.yaml`, a new pack) changes that digest, so no session has a row under it.
The next call then folds the session from its first event.

In a long session that fold outlasts the guard's 20 s taint budget. Each call saves
what it reached and is denied with `kernel-error`, and the next one reads on. That
should converge after a few calls, but it did not in a real session: 75,000 events,
six agents calling at once. Each call's save is written without waiting for the
database's lock (the guard is about to wait for it to record), and with six guards
recording, the saves were skipped. Every call started from nearly the same place and
was denied. The session was locked until it was abandoned. Nothing ran unchecked,
but a policy change must never make a session unusable.

## Decision

1. **Carry the earlier fold forward.** When a call's digest has no row further on
   than a carried one, the guard reads on from the session's furthest fold under any
   other digest of the same session and host. It classifies only the calls recorded
   since, under the new policy. That fold is kept in a carried row of its own (the
   digest with `carried` added, shared or per directory as ADR-020's note says), so
   it never mixes with the new digest's own fold.
2. **Never looser than before.** A carried fold holds everything the earlier policy
   (or build) found the session exposed to, plus what the new policy finds in the
   calls since. A change that loosens the policy keeps the earlier taint until the
   new fold catches up. That's the safe side: more reviews for a while, never fewer.
3. **The new policy's own fold catches up in the background.** Claude Code's
   `PostToolUse` hook (`taint::catch_up`) folds the new digest's own row from the
   first event, within its budget, saving as it goes. It never reads the carried
   row. Once that row reaches the carried row's event, calls read it, and the
   session's taint is again exactly what the new policy says.
4. **A fold holding a call recorded without a directory is never carried.** Such a
   fold took that call to have run in another directory (ADR-020's note), so the
   session is folded from its first event, as before.
5. **A timed-out fold's save waits for the lock.** That call is denied anyway. Its
   save is the only thing the next call can read on from, so it waits for the
   database's write lock (2 s) instead of being skipped. Every other cache write
   still skips while another guard holds the lock.

## Consequences

- The first call after a policy change in a long session folds only the calls
  recorded since, as any other call does. A test checks this for 2,000 calls and a
  change of the rule that made the first call a secret read: one call folded, the
  secret kept, and after a catch-up the new policy's own answer.
- **The gap, stated plainly:** until the new fold catches up, a call recorded before
  the change is judged as the earlier policy (or build) classified it. If the new
  policy or build would taint an earlier call that the old one did not (a tighter
  rule, a fixed classifier gap), later calls get that taint only once `catch_up`
  reaches the end. On Claude Code that is after the next call or a few calls. Hosts
  without a `PostToolUse` hook stay on the carried fold for the rest of the session;
  new sessions fold under the new policy from their first call.
- A session with no earlier row at all (its first call came under a build older than
  #570's table) still folds from its first event. With the waiting save, it now
  converges over a few calls instead of being held by concurrent guards.
- The cache stays outside the hash chain and is never a source of truth: a carried
  row only ever holds what earlier folds computed from the events.

## Alternatives considered

- **Keep the digest stable across policy changes.** Wrong: a cached fold under the
  old policy would be read as the new policy's, with no catch-up, forever.
- **Fold only a recent window under the new policy.** Bounded, but it drops what the
  earlier policy found in older calls. That loosens.
- **Raise the taint budget.** The guard's total budget is the host's hook timeout
  minus margin, and a long enough session outlasts any budget.

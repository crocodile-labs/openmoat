# ADR-064: A required protection level

Status: accepted · Date: 2026-11-07 · Builds on ADR-018, ADR-022, ADR-028, ADR-031, ADR-039 and ADR-059

## Context

`openmoat status`, `openmoat doctor` and the home screen show each agent's protection
level (`protection.rs`): `hook + OS sandbox`, `hook only`, `not protected`, `not set up`.
Nothing acts on it. An agent whose sandbox settings are gone, or one OpenMoat writes no
sandbox for, keeps working at `hook only`, where an allowed call runs with the person's
permissions and a classifier mistake is a bypass (LIMITS "Outside an OS sandbox, the
hook decides alone"). A person or a team that has decided the hook alone is not enough
for some agent has no way to say so, short of reading `status` every morning.

What can be known about the level, and from where, differs:

- **`openmoat status` and `doctor`** read everything: the hook entries, the agent's own
  settings that turn hooks off, a plugin's heartbeat (ADR-042), and the sandbox settings
  against the compiled sandbox plan.
- **The guard** runs inside one tool call, under the latency budget (`GUARD_BUDGET_S`,
  and the 15 ms p95 of the guard latency check). It knows that the hook runs (it is the
  hook), that the lock it verified first pins the hook entries as `openmoat init` wrote
  them (invariant 9), whether the call came through `openmoat run` (`--relayed`, ADR-028),
  and whether the host's sandbox is in place: `protection::os_sandboxed_by_lock`, which
  ADR-039's check already reads and keeps under the lock's digest in `sandboxed.json`.
  It cannot see a hook that does not run: no call reaches it.
- **`openmoat run`** is the OS sandbox. What it cannot give is the hook.

## Decision

1. **Schema.** An optional top-level `require:` section in the policy:

   ```yaml
   require:
     protection: hook-and-os-sandbox   # every agent; or hook-only
     agents:                           # by host id, in place of `protection` for that agent
       gemini-cli: hook-only
   ```

   The levels are the names `openmoat status --format json` gives them, read as "at
   least": `hook-only` < `hook-and-os-sandbox`. Absent, which is the default policy,
   nothing is required and nothing changes. An id in `agents` that is no host OpenMoat
   knows is an error (the core checks the form, the CLI the hosts): a typo would leave
   that agent's level out unseen.

2. **Sources, strictest wins.** A repository policy (ADR-022) and a policy pack
   (ADR-031) may have a `require:` section too. Each is a source; the level an agent must
   be at is the highest any source asks for (`Policy::required_for`). An agent's own line
   takes the place of `protection` only within its file. So a repository can raise the
   level and never lower it, whatever it writes, and needs no `openmoat trust` to raise
   it, as for its deny and review rules. A pack, installed by a person after its
   signature verified, raises it the same way. Messages name the source that asks
   (`your policy`, `the repository policy`, `the policy pack <name>`).

3. **The guard.** After the lock check, the MCP server check and loading the policy,
   when the calling agent has a requirement, the guard works out the level of the call:
   `hook + OS sandbox` inside `openmoat run` or where `os_sandboxed_by_lock` says the
   host's sandbox holds the call, `hook only` otherwise. Below the requirement every call
   is denied with the new built-in rule `protection-required`: governed calls, and tools
   OpenMoat does not govern, which otherwise go back to the host. The reason names the
   source, the two levels, what is missing and the one step that fixes it
   (`openmoat sandbox sync` where OpenMoat's settings for the host are missing or
   drifted, `openmoat run` for an agent OpenMoat writes no sandbox for, `openmoat edit`
   to lower that agent's line where no sandbox exists on the system). The block message
   (ADR-059) gets its title, `why` and `next` from the one table of built-in checks.
   Session starts and `ConfigChange` events are decided as before: they run no tool, and
   a session start only issues the session's `openmoat proxy` credential (ADR-044).
   Nothing required, nothing is read: the default costs one lookup in the loaded policy.
   Required, the sandbox answer is the kept one, so the cost is one small file read
   after the first call per lock; no process is started.

4. **Fail closed.** A sandbox answer that cannot be worked out or kept counts as no
   sandbox, so a `hook-and-os-sandbox` requirement the guard cannot confirm is not met.
   A policy, repository policy or pack that cannot be read denies every governed call
   with `kernel-error`, as before. For an ungoverned tool, whose decision reads no policy
   otherwise, the guard reads what a requirement needs (no repository signature check, no
   process) and leaves the host's own answer when that cannot be read: whether a level is
   required is then unknown, and every governed call is already denied.

5. **`openmoat run`** refuses to start, before it binds the proxy or builds the sandbox,
   when it cannot meet the level required of the program: `hook-and-os-sandbox` where it
   has no sandbox on this system; any level for a program that is no agent OpenMoat knows
   (no hook of OpenMoat's would check its calls; only `protection` applies to it); and
   for an agent whose hook does not run (the same check `status` makes). Inside the run,
   calls relayed to it meet `hook-and-os-sandbox`.

6. **`status`, `doctor`, the home screen.** Each agent's entry gains `required`: the
   level, the source, whether it is met, and when it is not, what is missing and the fix.
   An unmet requirement marks the agent `✗`, adds the row under it, and is a problem
   (exit 64) in both commands; the home screen says `below the required …`. They show
   the requirement in force in the current directory, repository policy included.

7. **The requirement is protected as the policy is.** The policy, the packs and their
   record are pinned by the lock, so an agent that takes the section out denies every
   call (`kernel-integrity`) until a person re-pins, and the repository policy is under
   `kernel-self`.

## Alternatives

- **Compute the full `status` level on every call.** It reads every hook file, the
  agent's settings and, for the sandbox, compiles the plan (tens of milliseconds). The
  hook entries are already covered by the lock; the sandbox answer is already kept per
  lock. The same answers, read once.
- **Let a trusted repository lower the level.** A repository is input the person did not
  write; trust widens its allow rules, which a deny still beats. A lower level would
  widen everything the requirement denies at once. Not allowed, trusted or not.
- **Leave packs out.** A team that ships its rules as a pack is the team most likely to
  want a minimum. Packs are installed by a person and can only raise it, as a
  repository can.
- **Require `not-protected` or per-tool levels.** A level below `hook-only` would deny
  nothing the guard can see; per-tool levels mix this with the rules. Not built.

## Consequences

- `openmoat-core`'s `Policy` and `RepoPolicy` gain public fields (`require`,
  `require_added`; `require`): a breaking change for code that builds them field by
  field.
- An agent below a requirement is unusable until the person fixes it, which is the
  point; `status` and the block message say how.
- The SDK and the WebAssembly module parse `require:` and keep it, but decide, never
  enforce: they do not apply it.

## Limits

- **A hook that does not run cannot deny.** Hooks turned off by the agent's settings, a
  plugin the agent did not load, a hook the agent skips when it fails (LIMITS "When an
  agent skips or changes the check"): no call reaches the guard. `status` and `doctor`
  show those agents as below the level, and `openmoat run` refuses them; nothing stops
  the agent started on its own.
- **The sandbox answer is as strong as the state directory.** `sandboxed.json` and the
  lock live in `~/.moat`, which `kernel-self` keeps from the agent's tool calls and
  every OS sandbox keeps from its commands. A program that runs as the person outside
  any sandbox can rewrite both, as it can rewrite the policy (LIMITS).
- **`hook-and-os-sandbox` means what `status` means.** Claude Code's sandbox holds its
  shell commands, not its file tools, `WebFetch` or MCP servers; Cursor runs some
  commands outside its sandbox. The level says OpenMoat's sandbox settings are in force,
  not that every call is confined.
- **The level is checked at each call, the sandbox settings are pinned.** A change to
  the host's sandbox settings after the lock is a lock drift and denies every call by
  itself; a change the lock lets through (`integrity/relaxed.rs`) is part of the kept
  answer's key.

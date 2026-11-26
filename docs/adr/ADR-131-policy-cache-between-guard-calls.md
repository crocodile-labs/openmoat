# ADR-131: Keeping the loaded policy between `openmoat guard` calls

Status: proposed (design, nothing built) · Date: 2026-11-26 · Builds on ADR-071 (the
binary's digest), ADR-080 (the latency budget and its 2026-11-26 amendment), ADR-101 (the
audit key), ADR-120 (the guard's phases), ADR-130 (the phase times)

## Context

Every hook call is a new `openmoat guard` process. Each one checks the lock, reads the
user policy, lints it, merges the `openmoat allow` overlay, the installed packs, the team
layer and the project's repository policy, compiles every pattern for the call's
evaluation context, and then decides. Nothing of that work is kept: the next call, a
second later, with the same files, does it again. ADR-080 ended with "Keeping a compiled
policy between calls would need its own integrity binding to the lock and is not part of
this decision". This ADR is that binding, and the choice of whether to build it.

### What the phases cost

On the user's machine, `openmoat bench` on `main` after #873 (ADR-130's per-phase line,
p50 in µs):

| Phase | What it covers in `commands/guard.rs` `evaluate` | p50 |
|---|---|---|
| `lock` | the payload's parse, `Home::locate`, `integrity::check` (every pinned file read once and hashed, the binary's digest from its cache), `placed`, the MCP pin check | 12,541 |
| `context` | `context::eval_context`, the decoy record, `repo::effective_policy` (`Policy::parse` with its lint, then the overlay, packs, team layer, recorded binary paths, MCP names and repository policy), the known secrets, the required level, the environment snapshot | 13,671 |
| `compile` | `CompiledPolicy::compile`, the first `decide_with`, the project settings check | 49,300 |
| `taint` | opening the audit log and the session checks | 23,196 |
| whole call | | 102 ms |

That run predates #874. In-process on the development Mac after #874 (ADR-080's
amendment, default policy of 105 KB, 80 KB in 0.19.0):

| Step | p50 / p95 ms |
|---|---|
| `Policy::parse` (deserialize and lint) | 6.5 / 10.4 |
| `CompiledPolicy::compile` | 12.9 / 20.0 |
| first `decide` | 0.3 to 0.6 p50 |
| parse, compile and first decide | 20.2 / 29.3 (36.6 / 66.3 before #874) |

The profile of #874 splits compile's 12.9 ms as about 62 % globset building each spelled
glob (its parse and the regex text it produces), 34 % `ShellPattern::compile` (lexing
each shell pattern and building each word's glob, so part of it is the same globset
work) and 10 % producing the spellings (`~`, `${project}`, the real and moved
directories, both case modes). The shares overlap and do not add to 100 %.

Two facts bound what keeping state between calls can save:

1. **Compile cannot be kept.** A `CompiledPolicy` holds globset matchers and the regexes
   behind them. `openmoat-core` depends only on `serde`, `serde-saphyr`, `globset` and
   `thiserror` (invariant 7); globset's `Glob` serializes as its source text and builds
   again when read back, and nothing in these crates writes a regex out. Keeping a
   compiled form needs another dependency in the core (a regex engine whose automata can
   be written to bytes), which needs an ADR of its own and would replace globset's
   matching, which every never-widen proof (`widen/proof.rs`) reads.
2. **Parse is the part that can be kept, and it is the smaller part.** After #874 it is
   6.5 ms of the 20.2 ms in-process; compile is 12.9 ms. On the user's machine the
   `lock` and `taint` phases together (35.7 ms) are larger than parse and compile were in
   process, and keeping the policy changes neither of them.

The user's numbers above have not been taken again since #874; the first step below
does that, because it decides how much of `context` and `compile` is left to save.

## Options

Each gain is an upper bound from the in-process p50s above; none is measured. "Saves"
means time a call no longer spends; what the option adds back is named beside it.

### A. Keep the merged, linted `Policy` (the output of `effective_policy`)

A call whose inputs all match an entry reads the policy from the entry instead of
parsing, linting and merging, then compiles it as today.

- **Saves:** `Policy::parse` (6.5 ms, about half deserializing the YAML and half the
  lint) and the merge steps (not measured separately; the overlay, packs, team layer and
  repository policy are small next to the default policy).
- **Adds:** reading the entry, one HMAC-SHA-256 over it (the same order of bytes the
  lock check already hashes for the policy file) and deserializing it from JSON with
  `serde_json`, which the CLI already depends on. The JSON read is likely faster than the
  YAML one, but by how much is for the bench to say, not this ADR.
- **Net:** at most about 6 ms of 20 ms in-process, about 6 % of the user's 102 ms call.
  Compile stays at 12.9 ms.
- **Touches:** only `openmoat-cli`. `Policy` already derives `Serialize` and
  `Deserialize`.

### B. Keep A plus the spelled pattern texts

The entry also holds every pattern already spelled for the context, so compile skips the
spellings and the shell lexing and goes straight to globset.

- **Saves:** A, plus the spellings (about 10 % of compile, 1.3 ms) and the lexing part
  of `ShellPattern::compile` (not measured on its own). About 7 to 9 ms at most.
- **Adds:** a constructor in `openmoat-core` that builds a `CompiledPolicy` from spelled
  texts it did not produce. A forged entry would then hand the engine patterns directly,
  not a policy the engine spells itself, so a mistake in the binding below would reach
  further than in A. The spelled texts also bind the entry to the whole evaluation
  context, so a new working directory inside the same project still hits, but a new
  project, home or moved directory misses.
- **Globset's build (about 62 % of compile) stays.**

### C. Keep the compiled matchers

Not possible with the core's dependencies (fact 1). Rejected here; it would need its own
ADR for a new core dependency and a new matcher under the never-widen proofs.

### D. A long-running guard service

One process keeps the compiled policy (and could keep the audit log open and the
session folds in memory) and each `openmoat guard` hands it the payload over a local
socket, as a guard inside `openmoat run` already hands its call to the run (ADR-028).

- **Saves:** parse and compile (about 19 to 20 ms in-process), and possibly part of
  `taint`, the largest phase on the user's machine. The process start and the `lock`
  phase stay: the hosts still start one process per hook, and the lock must still be
  checked on every call against the files on disk.
- **Adds:** who starts it, who stops it, what happens after an upgrade (the running
  service is the old binary), and how the guard knows the process on the socket is
  OpenMoat's. Every process of the agent runs as the same account, so an agent could
  start its own listener on the socket's path and answer `allow`; the guard would have
  to authenticate the service (for example a challenge answered with a MAC under the
  audit key) and fall back to deciding in-process when it cannot. It is a new kind of
  component with its own threat model, not an optimisation of the existing one.
- **Needs the user's decision:** whether OpenMoat may run a background process at all.

### E. Build each glob only when a call first matches against it (no state kept)

Today `GlobPattern::compile` calls globset's `GlobBuilder::build` for every pattern
when the policy is compiled, and only the matcher behind it is built lazily
(`pattern/lazy.rs`). The literal start and the literal end (`Tail`) that refuse most
candidates are computed from the glob's text, not from globset's result. So the build
could also wait for the first candidate that passes both checks.

ADR-080's amendment left this out because `build` can fail and a deferred failure would
need "an error branch inside the matcher with no safe answer for an allow list". This
ADR proposes the answer:

1. The lint already proves, when the policy is loaded, that every pattern parses
   (#874: it builds those that may fail and a test covers every short string of the
   other glob characters). Only the spelled form can still differ, when a home or
   project path holds glob syntax.
2. A deferred build that fails sets a failure mark on the `CompiledPolicy`, and the
   matcher answers in the strict direction for its list: a deny or review glob, or an
   allow list's exclusion, counts as matched; an allow glob or a deny list's exclusion
   counts as not matched.
3. After each decision the guard reads the mark, and a set mark turns the call into the
   guard's error deny (invariant 4), as a compile error does today. The SDK does the same
   in its `decide`.

So the outcome of a failure is the same deny as today, one decision later.

- **Saves:** most of globset's share of compile (about 62 % of 12.9 ms, so up to about
  8 ms), less the builds the first decision still needs (those whose literal start and
  end let a candidate through; #874 cut the first decision to 0.3 to 0.6 ms with the
  same filters).
- **Adds:** no file, no key, no new trust. The cost is a pure change in `openmoat-core`
  and one check in the guard and the SDK.
- **Needs the user's decision:** it reverses the conclusion ADR-080's amendment
  recorded.

A per-kind variant (compile only the kinds the action touches: no shell patterns for a
file tool's call) saves less and is mostly covered by E: shell patterns are 34 % of
compile, but a `Bash` call needs them all.

### F. Make compile cheaper in other ways

The #874 profile leaves little: sharing each repeated shell word's glob measured inside
the run-to-run spread (ADR-080), and the spellings are 10 %. Nothing to decide here
beyond E.

### G. Do nothing

Parse, compile and the first decision are 20.2 ms p50 in-process, at ADR-080's 20 ms p95
target for Linux runners. The user's machine spends more of the call outside these
phases than in them.

### Summary

| Option | Saves (in-process p50, upper bound) | New trust | Code |
|---|---|---|---|
| A. Keep the merged policy | about 6 ms | a keyed file in the state directory | CLI |
| B. A plus spelled texts | about 7 to 9 ms | the same, reaching the engine | CLI and core |
| C. Keep compiled matchers | most of 19 ms | the same, plus a core dependency | rejected |
| D. Guard service | about 19 ms and part of `taint` | a socket and a process to authenticate | new component |
| E. Deferred glob build | up to about 8 ms | none | core and guard |
| F. Other compile work | about 1 ms | none | core |
| G. Nothing | 0 | none | none |

## Decision

### 1. Order: measure, build E, then measure again before any cache

1. Run `openmoat bench` on the user's machine on `main` after #874 and record the phase
   line. The table above is from before #874; how much of `context` and `compile` is
   left decides what any option can save there.
2. Build E (deferred glob builds with the failure mark), if the user accepts reversing
   ADR-080's amendment. It saves the most of the options that keep nothing on disk.
3. Build the cache below (option A) only if, after E, `Policy::parse` and the merge are
   still a share of the call worth a new state file. The threshold is a question for the
   user (see the end of this ADR); it should be stated as a number before the work
   starts, not chosen after it.

D is not proposed. B is not proposed: it adds at most 1 to 3 ms over A and lets a
forged entry reach the engine's patterns directly.

The rest of this decision is the design of A, so that if step 3 says build it, its
binding is already settled.

### 2. What is kept

The `Policy` that `repo::effective_policy` returns for one call (user policy, overlay
rules in force, packs, team layer, recorded binary paths, MCP names, repository policy
merged), before `decoys.guard`, serialized with `serde_json`. The decoys come from the
canary record, a pinned file, and are applied after the load as today, so the entry
does not need to know about them. The lint's result is part of what is kept: a policy
is written to the cache only after it parsed and linted, so a hit skips both.

Nothing compiled is kept.

### 3. What an entry is bound to

An entry is used only when every input that produced it is the same now. A mismatch on
any of them is a miss; there is no partial match and no fallback to an older entry.

1. **The lock and what it pins.** The SHA-256 of the lock file's bytes as
   `integrity::check` read them, and `Kept::drift_digest` of the relaxed drift the call
   is decided through (empty for none). The lock holds the digest of every pinned file:
   the policy, `approvals.json` and its overlay, `trust.json`, `hosts.json`, the
   canary and start records, the packs record and each installed pack, the team record,
   bundle and rules. While the lock check passes, each of those files is the bytes its
   pin names, so the lock's own digest stands for all of them; a re-pin changes it. No
   pinned file is hashed a second time.
2. **The inputs the lock does not pin.** The repository policy is the project's file,
   not the person's state, and so are the files `repo::find` looks for and the
   signature it checks. The loader records each file it reads outside the pinned set as
   path and SHA-256, each path it probed and found missing as absent, and each directory
   it listed with the names it found. The entry stores that list; a lookup reads and
   hashes each path in it again (a repository policy is a few kilobytes) and misses on
   any difference.
3. **The evaluation context, without the working directory.** `home`, `project`,
   `real_home`, `real_project`, `moved_dirs` and `case_insensitive_paths` of the call's
   `EvalContext`. The loader reads `project`; the rest are bound as well so that one
   entry is never shared between two homes or two moved directories, even where the
   loader does not read them today. `cwd` is not bound: the policy does not depend on
   it, and compile runs afresh with the call's own context.
4. **The environment.** The variables the loader reads (`MOAT_HOME`, `HOME`, each host's
   directory variable, through `context::moved_dirs` and `home.rs`) are already in the
   context's fields. Any other variable the loader comes to read must go through the same
   recording accessor as files do, which stores its name and value digest in the entry.
   An architecture test rejects a direct `std::env` read in the loader's modules.
5. **The clock.** `Overlay::in_force` keeps a grant only inside its window (ADR-007's
   amendment of 2026-11-08), so the same files give another policy once a window opens
   or ends. The entry stores the next instant at which any window it saw opens or ends;
   at or after that instant it is a miss. Any other clock read in the loader must report
   its next boundary the same way, or the load is not cached.
6. **The binary and the format.** The running binary's SHA-256 (from the digest cache of
   ADR-071), its release (`binary::VERSION`) and a cache format number. Another build
   parses, lints and merges by other code, so it never reads this build's entry.

The entry's file name is the SHA-256 of items 1, 3, 4 and 6, so the lookup finds at
most one candidate without reading any other entry; items 2 and 5 are checked inside
it.

### 4. Integrity: where it lives and why a forged entry is not used

**Where.** `~/.moat/cache/policy/<name>.json` (under `MOAT_HOME` when set), written
readable by the person's account alone with `home::write_private` through a temporary
file and a rename. At most 16 entries are kept; a write removes the oldest beyond that,
best effort. The directory is not pinned by the lock: the guard rewrites it on its own,
as it does `binary-hash.json`.

**Who can write it.** The guard, as the person's account. `kernel-self` already denies
agent writes to the state directory, and the host sandboxes and `openmoat run` carry
that deny. The entries hold the overlay's rules and trusted repository policies, so
`kernel-self` gains read denies for `~/.moat/cache/policy/**` and
`**/.moat/cache/policy/**`, as for `approvals.json` (a change to the default policy,
with an attack and a benign fixture).

**Why the binding above is not enough on its own.** Every input in section 3 can be
read by whoever reads the state directory, so a process that can write
`~/.moat/cache/policy/` could write an entry under the right name holding a looser
policy. The lock does not stop it: the lock pins `policy.yaml`, and the guard would
never read `policy.yaml`. Unlike a forged lock and policy, which `openmoat status`,
`doctor` and the policy file itself show, a forged entry would leave every file a
person checks looking intact.

**The MAC.** Each entry is `{"mac": …, "body": …}`, where the MAC is HMAC-SHA-256 over
the body's bytes under a key derived from the audit key: `HMAC(audit key, "openmoat
policy-cache v1")`, with `openmoat_audit::hmac_sha256`, which the audit log already
uses (no new dependency). The guard reads the audit key with `key_file::read`, which
refuses a key others may read or replace. Before it parses the body, the guard computes
the MAC and compares it in constant time; then it compares the body's binding with the
call's. Only then is the policy deserialized.

Forging an entry so needs the audit key, which `kernel-self` and the sandboxes deny to
agents for reading. That is the same bar as rewriting the audit log so that it verifies
(ADR-101), and higher than rewriting the lock, which needs no secret. A process that can
read the audit key (code running as the person outside every hook and sandbox) can
forge entries, as it can rewrite the log, the lock and the policy; this cache does not
change what such a process can do (THREAT_MODEL §5).

**Replay.** An entry made earlier, under a looser policy, carries a valid MAC. It is
refused because its binding names the lock as it was then: a re-pin that tightened the
policy changed the lock's digest. To get the old entry used, the lock and every file it
pins would have to be back as they were, which is the looser state itself, visible to
`status` and `doctor` as any lock change is.

**No audit key, no cache.** Without a usable audit key (before `openmoat init`, a
deleted or unsafe key file), the guard neither reads nor writes entries and loads the
policy as today. It never makes a key for the cache (ADR-101 says why a writer must not).

**Options weighed for the integrity.**

| Way | What it gives | Why not chosen, or why chosen |
|---|---|---|
| MAC under a key derived from the audit key | a forged or edited entry is found before use | chosen: no new secret, no new dependency, refreshed by the guard itself |
| Recompute and compare | certainty | costs the full parse the cache is there to save; a sampled re-check finds a forged entry only after it was used. Kept as a debug-build check for tests (section 6) |
| Only a person's re-pin writes the entry, and the lock pins its digest | trusted exactly as much as the lock, no key | covers only the user layer (no repository policy), misses after every grant window boundary or upgrade until the next re-pin, and adds a file to every lock check. An alternative the user may prefer (questions below) |
| No integrity check | none | rejected: a forged entry would loosen decisions while every checked file looks intact |

### 5. Fail closed

The cache only ever replaces work with the same result; it never decides.

| Case | What the guard does |
|---|---|
| No entry under the name | full load, then write the entry |
| Unreadable file, not JSON, wrong format number | full load, then rewrite |
| MAC does not verify | full load, then rewrite; the miss is counted in the bench line, not reported per call |
| Binding differs (a file, a context field, a variable, past the window) | full load, then rewrite |
| Body verifies but does not deserialize | full load, then rewrite (a build that changed `Policy` without changing the format number; a test guards against it) |
| No usable audit key | full load, no write |
| Full load fails (a policy that does not parse, a repository policy that does not merge) | the call's error, as today: deny (invariant 4); nothing is written |
| Two guards write the same name | each renames a whole file over the other; a reader sees one whole entry or the other, both valid or both refused by the MAC |
| The write fails (disk full, permissions, a read-only home) | the call is decided as usual; nothing is said per call |

The lock check runs before the cache is looked at and is unchanged: a drift that denies
today denies before any entry is read. The cache is written after the response is
printed, so a slow write does not count against the deadline (ADR-120).

### 6. Tests and measurement

Tests that prove a stale or forged entry is never used:

1. **One test per binding input** (table-driven): build an entry, change exactly one
   input (each pinned file through a re-pin, the lock bytes, a relaxed drift, the
   repository policy's bytes, its appearance, its removal, its signature, each context
   field, each recorded variable, the binary's digest, its release, the format number,
   the clock past a grant's window), and check the next call misses and decides as a call
   without a cache does.
2. **Forgery:** an entry with one byte of its body changed; a body moved under another
   entry's name; an entry with an added allow rule and a MAC under another key; an entry
   made under a looser policy kept from before a tightening re-pin. Each is refused, and
   the call that follows decides as with no cache.
3. **Corruption and concurrency:** truncated, empty, not JSON, a directory in its place,
   a file the guard cannot read, a cache directory it cannot write, and many guards on a
   cold cache at once. Each call decides correctly and none fails for the cache.
4. **Equivalence:** the conformance fixtures, run through the guard with the cache cold,
   warm and turned off, give the same verdicts and rules. A property test applies a
   random sequence of policy edits and re-pins and compares each decision with and
   without the cache.
5. **A check mode for debug builds:** with a variable that only debug builds read, as
   `MOAT_ASSUME_TTY` is, every hit also loads the policy in full and denies on any
   difference. The end-to-end suite runs with it. It only makes a call stricter, so it is
   no way around a check.
6. **Round trip:** every policy the conformance runner loads deserializes from its JSON
   form to an equal `Policy`, so a field `serde_json` drops fails a test, not a call.

For E, the same equivalence test (4) with and without deferred builds, and a test that a
spelled glob that fails to build sets the mark and the guard denies the call.

Measurement:

- `openmoat bench`'s per-phase line (ADR-130) on the user's machine before and after
  each step, p50 and p95 of `context` and `compile`, with the cache's hits and misses
  counted in the same output, so a run that missed every time is not read as a gain.
- CI's latency comparison (ADR-080: the commit before and this one, timed in turn on
  the same runner) shows the guard's own p95 for each change. The PR reports both.
- The weekly long-session bench (ADR-080 decision 3) shows whether entries pile up or
  the hit rate falls late in a session.

## Consequences

- Nothing changes until the first measurement; this ADR settles the order and, if a
  cache is built, its binding, so the work is not designed under time pressure.
- If E is built, ADR-080's amendment's conclusion about deferred builds no longer holds;
  that amendment stays as written and this ADR records why.
- If the cache is built, the state directory holds one more kind of file, with read
  denies in `kernel-self` and the sandboxes, removed by `openmoat uninstall`, left out of
  `openmoat doctor --bundle`, and named in ARCHITECTURE.md and THREAT_MODEL.md §5.
- A cache saves at most the parse (about 6 ms in-process). It does nothing for the
  `lock` and `taint` phases, which on the user's machine took 35.7 ms of a 102 ms call.

## Questions for the user before any code

1. May E reverse ADR-080's amendment, with the failure mark as the answer for a deferred
   build that fails?
2. What share of the call must parse and merge still take after E for the cache to be
   worth building (for example "over 5 ms p50 on the user's machine")?
3. If a cache is built: the MAC under a key derived from the audit key (refreshes
   itself, covers repository policies), or an entry only a person's re-pin writes and
   the lock pins (no key, user layer only, misses until the next re-pin)?
4. Is a background guard service (D) out of scope, or worth its own ADR for the `taint`
   phase, which no option here touches?

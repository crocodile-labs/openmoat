# ADR-111: Check every policy change for widening, and prove it where the rules are regular

Status: accepted, released in 0.26.0 · Date: 2026-11-22 · Builds on ADR-019 (one policy, compiled; lowering
never widens), ADR-022 (repository policy), ADR-031 (policy packs), ADR-050 (merge
check), ADR-062 (request rules)

## Context

ADR-019 makes the policy compiler narrow and never widen, and `ir_never_widens.rs`
tests that lowering a policy to an OS layer never allows what the engine does not.
Nothing checked the other direction that matters to a person: whether a *change* of
the policy (an upgrade of the default, a trusted repository policy, a new pack
version, a pull request that edits `.moat/policy.yaml`) lets something through that
the old policy held. A reviewer read the diff. A defer → allow change once shipped a
bypass (#512): the class of mistake a diff shows as a few harmless lines.

Comparable products check this formally: NVIDIA OpenShell runs a prover on agent
proposed network rules and blocks auto-approval when a change adds credentialed reach
or new HTTP methods. Cedar's analysis tools decide policy inclusion with an SMT
solver. OpenMoat's core may depend only on `serde`, `serde-saphyr`, `globset` and
`thiserror` (AGENTS.md invariant 7), so no solver is available in the tree.

## Decision

1. **One library check, `openmoat_core::widen::compare(old, new, contexts, corpus)`.**
   It decides both compiled policies on the verdict lattice
   deny > review > defer > allow and reports every case whose verdict moves toward
   allow, with the rules that decided it before and after. In each evaluation
   context it decides:
   - **the corpus**: whole calls (`CompiledPolicy::decide`, every layer: folders,
     taint, request rules, pins). The CLI passes the bundled MoatBench steps;
     `policy diff --fixtures` adds conformance files; the core's test passes every
     conformance fixture;
   - **generated boundary cases** from the rules of *both* policies, so a rule that
     was removed or changed has its own edges decided: each path pattern's matches
     (wildcards empty, one word, two levels deep), its literal folder, a sibling and
     the folder of `dir/**`; each host pattern's matches and lookalikes
     (`wgithub.com`, `github.com.w`); each shell pattern's argument lists, as the
     atom and as a command; each environment and MCP name pattern; each `requests:`
     rule with its own and seven common methods, wildcards filled, with and without
     a trailing `/` and in capitals; and one case per kind no rule names, which only
     `defaults` decide;
   - **a symbolic search** (below) for every subject of the kinds a glob decides.

   Two reductions keep it fast without skipping anything that could widen. Within a
   list the order of groups changes only the rule ids named, so when both policies
   give a kind the same default, an atom that no pattern matches which is in one
   policy and not in the same place (list, group, kind, exclusion) of the other gets
   the same verdict from both: only atoms such a pattern matches are decided, and the
   search stops following a string once every such pattern that may lower a verdict
   is dead. A change that can only hold more is not one of those: a pattern added to
   a deny group, or to a review group where the kind's default is not `deny`; an
   exclusion taken out of such a group; an exclusion of such a group the old policy
   does not have (`/usr/**` without `/usr/local/**` in a new review group). The search also
   stops following a string once the least verdict the new policy can still give it
   is at least the greatest the old one can (a deny pattern that matches whatever
   follows, an allow that does). Whole calls, the costly part, are decided in the
   first context only.

   Settings outside the rules are compared one by one with their direction
   (`sandbox.read_roots` added, `executables` pin removed, `require_signed_repo_policy`
   off, `unattended: defer`, `mcp.trust_first_sight`, a lower default, …). A setting
   whose direction is not ranked (`taint`, `staging`, `check_diff`, `require`, a
   changed brokered secret) is reported as *changed, not ranked*: a person looks at
   it, as at a widening. Rule groups and request entries added, removed, moved to
   another list or changed are listed for the reader.

2. **What is proven, and how.** For `fs.read`, `fs.write`, `net` (and words that look
   like hosts), `fetch`, `env.read`, `env.set` and `mcp`, the per-atom verdict
   (`evaluate_atomic`: deny, repository review, allow, review, defer, default) is a
   boolean combination of regular languages. The check reads each pattern as the
   regular expression globset itself matches with (`Glob::regex()`, a small fixed
   subset of syntax, read as an automaton over bytes; anything outside the subset
   leaves the kind *not proven*), walks the product of every pattern of both policies
   breadth first over the byte classes no automaton tells apart, and at each state
   computes both verdicts. The walk is finite. When it ends without a state where the
   new verdict is lower, no subject of that kind widens for that context: a proof
   over every string, not a sample. A state that widens yields the shortest string
   reaching it, which the engine then decides; only a confirmed string is reported.
   An allow rule's `host:port` patterns, which apply only to a host written with a
   port, are over-approximated on the safe side (the new policy may use them, the
   old one may not), so a string the engine does not confirm leaves the kind not
   proven rather than reported. The search stops unproven past 250 000 states.
   `web.search` and `tool.unknown` are decided by `defaults` alone and are compared
   exactly. **Checked over cases only**, never called proven: shell commands
   (patterns over words of words), request rules, and whole calls with their folder,
   taint, request and pin layers. Every report says which kinds were proven in which
   context.

   The proof is per evaluation context: `${project}` and `~` are expanded for a home
   and project. The CLI checks two contexts, the conformance suite's
   (`/Users/me`, `/p`, file names with case) and a Linux-style one whose file names
   compare without case.

3. **Where it runs.**
   - `openmoat policy diff OLD NEW` lists changed rules and settings;
     `--widen` runs the check, prints each widening and what was proven, and exits 0
     when nothing widens, 2 when something does, 3 when only an unranked setting
     changed; `--format json` gives the whole report.
   - `openmoat policy upgrade` shows what the upgrade widens under its summary, and
     applies a widening upgrade only with `--accept-widening` (still only a person at
     a terminal; `--yes` does not imply it). An upgrade that only narrows says so.
   - `openmoat trust` shows what trusting the file widens (the person's policy with
     the file merged untrusted against merged trusted); `openmoat policy install`
     shows what the pack, or its new version, widens.
   - `openmoat policy check-diff --base` (and so the merge-check Action) compares the
     policy files the check reads, as the base and the head have them, with the
     repository policy merged as trusted: each widening is a `deny` finding
     `diff-widens` on that file, each unranked setting a `review` one. The existing
     `diff-policy` review finding stays.

4. **No new dependency.** The automata, the search and the sampler are about 900
   lines of the core, pure, with no solver. An SMT or Cedar backend stays possible
   later (roadmap L2); the regular part needs none.

## Consequences

- A change of the #512 class (calls the agent's own prompt decided now run unasked)
  is a CI failure in a repository and a question at the terminal, listed case by
  case with the rule that opened it.
- The check proves less than it may seem for the shell: a shell rule change is caught
  only where a generated or bundled case meets it. Classifier changes (how a command
  becomes atoms, which is where #512 itself was) are not policy changes and are not
  covered; the conformance suite remains their check.
- The text says "proven" only for kinds the search finished, per context, and
  "checked over cases" for the rest. A kind the search could not finish is named with
  the reason.
- The glob reader is tested against globset on every glob shape the default policy
  uses; a globset release that writes other syntax makes the affected kinds
  "not proven", never wrongly proven.
- `policy upgrade` of a widening default needs one more flag; an upgrade that only
  narrows (0.24.0 → 0.25.0: `env-dump` and `kernel-self` deny more) needs none.

# ADR-077: `openmoat run` can be required to start only with its full boundary

Status: accepted · Date: 2026-11-10 · Builds on ADR-018, ADR-028, ADR-049, ADR-064 and ADR-076

## Context

`require:` (ADR-064) sets the least protection level of each agent. It says nothing about
`openmoat run` itself, which degrades quietly in two ways. On Linux without a usable
bubblewrap the default `--netns=auto` restricts the network by port only and warns: a
command can reach any host on the proxy's port. And an inherited variable reaches the
agent unless it holds a brokered secret, cloud credentials included. A person or team
that has decided these are not acceptable could say so only with a flag on every run.

## Decision 1: `require.run: full-boundary`

```yaml
require:
  run: full-boundary
```

1. **Part of `require:`, not a new system.** The setting is read wherever `require:` is
   read: the person's policy, a repository policy and a pack. Any one source turns it on
   and none turns it off (`Policy::run_boundary_required`), as levels only rise. It is
   protected as `require:` is (ADR-064 section 7).
2. **What it refuses.** Before anything starts: a system with no OS sandbox OpenMoat can
   generate (macOS before 13, a missing backend, Windows). After the sandbox is built and
   before the agent starts: a Linux system where the agent would get no network namespace.
   The refusal names the policy that asks and how to get the namespace. `--netns=auto`, the
   default, and an explicit `--netns=auto` do not lower it.
3. **It applies to every program `openmoat run` starts,** agent or not, and so to an MCP
   server started through `openmoat mcp proxy --sandbox`, which is `openmoat run` around
   the server.
4. **`status` and `doctor`** report whether it holds on this system, and an unmet
   requirement is a problem (exit 64). `--format json` of `status` has `run_boundary`
   (`by`, `met`, `gaps`), `null` without the setting. Without the setting nothing changes.

## Limits of decision 1

- **It is about `openmoat run`.** An agent started without it is not refused: no OpenMoat
  code runs at that point. `require.protection: hook-and-os-sandbox` is what denies such
  an agent's calls (ADR-064), and the two can be used together.
- **On Linux the full boundary does not mean `--isolate`.** Plain `openmoat run` leaves
  paths inside the project open to commands (Landlock grants whole trees, `tier.rs`), and
  the setting does not change that; `openmoat run` still says so when it starts. Requiring
  `--isolate` would refuse every system without a working bubblewrap and every run that
  needs the rest of the machine readable, and was not asked for here.
- **The check is of this system at this moment.** `status` reads what `openmoat run` would
  find; bubblewrap removed afterwards is refused by the run, not by `status`.

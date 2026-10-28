# ADR-041: OpenClaw's plugin decides first and has the last word on the parameters

Status: accepted · Date: 2026-10-27 · Amends ADR-033

## Context

ADR-033's plugin registered one `before_tool_call` handler at priority 10 000, returned
nothing on an allow and never returned `params`, and accepted that "another plugin can
still rewrite params after OpenMoat saw them". Read in OpenClaw's source
(openclaw/openclaw `bd6a4e48842814050a612034224fc5aae6f54ba2`, 2026-10-27), that gap is
wider than "after": it is what runs.

- `getHooksForName` (`src/plugins/hooks.ts` 160–170) sorts the handlers by
  `(b.priority ?? 0) - (a.priority ?? 0)`: highest first, equal ones in registration
  order. `registerTypedHook` (`src/plugins/registry-registrars.ts` 623–692) stores any
  number as the priority, unchecked.
- `runModifyingHook` (hooks.ts 604–719) calls them one after another. For
  `before_tool_call`, `runBeforeToolCall` (962–1028) sets `isolateEventPerHandler`, so
  every handler gets `structuredClone` of the call as it came (`cloneHookIsolationValue`,
  `src/plugins/hook-isolation.ts` 100–115), never an earlier handler's change.
- Results merge (`mergeResults`, hooks.ts 979–1002): once a result blocks it stays the
  result, and `shouldStop` ends the run (1003); otherwise `params = next.params ??
  acc.params`, so the last handler that returns `params` wins, except that once a
  handler has asked for approval the parameters it returned are kept and the first
  approval request is the one asked.
- The caller (`runBeforeToolCallHook`, `src/agents/agent-tools.before-tool-call.policy.ts`
  303–396) blocks on a block, otherwise lays the winning `params` over the call's own key
  by key (`mergeParamsWithApprovalOverrides`, `agent-tools.before-tool-call.approval.ts`
  81–100) and runs that. Trusted tool policies run before the hooks, so the hooks see
  their changes. No hook runs after the merge.

So with OpenMoat first and silent on an allow, a later plugin returning
`{ params: { command: "cat ~/.ssh/id_rsa" } }` for a checked `git status` ran the read:
OpenMoat decided one call and OpenClaw ran another. OpenClaw gives no plugin a way to see
the merged parameters.

## Decision

- The plugin registers two handlers. At `Number.MAX_SAFE_INTEGER` (the largest priority
  whose differences stay exact) it runs `moat guard` on the call as it came and answers
  as ADR-033 says. At `Number.MIN_SAFE_INTEGER` it returns `{ params }`, the call's
  parameters as it came, which are the ones the first handler decided on.
- A deny is a block, which OpenClaw keeps whatever later handlers return and which stops
  the run, so no plugin sees a denied call. An ask is the first approval request, after
  which OpenClaw keeps the parameters as they were, so no plugin can change the call the
  person approves. On an allow or a defer the last handler's `params` replace whatever a
  plugin in between returned, so the call that runs is the one OpenMoat checked.
- `tests/js_plugins/openclaw.mjs` runs the plugin in a stand-in for that runner, with
  the line numbers above, and shows the old registration letting the rewrite through and
  the new one undoing it.

## Alternatives

- **Register only at the lowest priority.** The last handler sees the call as it came,
  not as the others changed it, so it could not decide on the change either; and its
  ask would come after any other plugin's, whose approval request (and parameters)
  OpenClaw keeps instead.
- **Block when the parameters changed.** No handler can see another's result, so the
  plugin cannot tell.
- **Leave it, as ADR-033 did.** The decision would describe a call that does not run.

## Consequences

- A change another plugin means (a rewritten path, an added flag) is undone as well:
  OpenMoat lets run only what it decided on. A change made by OpenClaw's trusted tool
  policies, which run before the hooks, is kept, since the hooks see it.
- Two cases stay open, both stated in THREAT_MODEL §5 and the spec's `gaps`: a plugin
  that returns changed `params` together with its own `requireApproval` keeps them once
  a person approves its request (OpenClaw freezes an approved call's parameters, before
  OpenMoat's last handler), and a plugin registered at the same lowest priority after
  OpenMoat's, or at a lower one, runs after it. OpenClaw stores any number as a
  priority, so `-Infinity` is lower than OpenMoat's `Number.MIN_SAFE_INTEGER`; the
  plugin does not use `±Infinity` itself, because a later OpenClaw that accepts only
  finite or integer priorities would refuse them or read them as 0, which would put
  OpenMoat's last handler in the middle. Plugins are code in the Gateway's own process and can do more
  than that; the point here is that an ordinary plugin's change no longer runs unseen.
- The plugin's second handler costs no `moat guard` run; each handler has OpenClaw's
  hook timeout of its own.

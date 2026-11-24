# ADR-124: Windows `openmoat run`: why the network and reads stay the hook's for now

Status: accepted · Date: 2026-11-24 · Builds on ADR-115 (the write-restricted Windows
tier, its §4, §5 and §7), ADR-108 (protection score), ADR-018 (OS enforcement)

## Context

ADR-115's Windows tier holds writes (a write-restricted token) and the process tree (a job
object). Its score weighs `wfp_network` 30 and `windows_read_deny` 15, both missing, so a
Windows run scores 55. This ADR records the design examined to add per-run network
filtering through the Windows Filtering Platform (WFP) and read denial through the token,
using only documented Win32 calls through the `windows-sys` dependency the CLI has, and
why neither is built yet.

## What was examined

### Network: a WFP filter per run

The shape: open a dynamic session (`FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC`, so
every filter goes when the session's handle closes, also when `openmoat run` is killed),
add a sublayer and, at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/`_V6` and the `RECV_ACCEPT`
layers, a block filter for the run's processes with one permit for `127.0.0.1` and the
proxy's port, as the Linux namespace and the macOS profile allow.

Two documented facts stop it:

1. **Adding a filter needs administrator rights.** The Base Filtering Engine's default
   security descriptor grants `GENERIC_ALL` to Administrators, read, write and execute to
   Network Configuration Operators and a few system services, and only
   `FWPM_ACTRL_OPEN` and `FWPM_ACTRL_CLASSIFY` to everyone
   ([Access control, WFP](https://learn.microsoft.com/windows/win32/fwp/access-control));
   `FwpmFilterAdd0` needs `FWPM_ACTRL_ADD` on the filter container. `openmoat run` starts
   unelevated, like the agent. Granting the person `FWPM_ACTRL_ADD` on the container once,
   from an elevated setup, would let every process of that person add filters, the agent's
   own outside a run included: a change to the machine's firewall that is wider than what it
   buys.
2. **No documented condition matches "this run's processes".** The candidates are
   `FWPM_CONDITION_ALE_APP_ID` (an executable's path: `node.exe` and `git.exe` are the
   person's too, and the agent starts many programs), `FWPM_CONDITION_ALE_PACKAGE_ID`
   (AppContainer, which ADR-115 rejected) and `FWPM_CONDITION_ALE_USER_ID`, a security
   descriptor the engine checks the connecting process's token against. The run's token
   differs from the person's only in its restricting SIDs, and it is *write*-restricted:
   Windows checks those SIDs on write access alone. Whether the engine's match right counts
   as write access for that check is not documented, so a filter on the run's own SID could
   match nothing, and the run would score points for a block that is not there. A
   dedicated local account per run (Codex's elevated design) matches cleanly, but needs
   administrator rights to create and its password to start a process.

### Reads: the token

- A write-restricted token is checked against its restricting SIDs on writes only
  (ADR-115 §4), so a deny entry for the run's SID on `~/.ssh` does nothing for reads.
- A deny entry for a SID in the token's ordinary groups (the person's SID, the logon
  session's) denies the person's own programs too.
- A fully restricted token (no `WRITE_RESTRICTED`) checks every access against the
  restricting SIDs. Then the person's profile, which grants the person alone, becomes
  unreadable except where the run grants its SID: the agent's settings, npm's and Cargo's
  caches, `.gitconfig`. That is AppContainer's shape again, which ADR-115 and Codex
  rejected for open-ended developer work, and it would need a grant on every folder an
  agent and its tools read.

## Decision

1. Nothing is added to the Windows tier now: `wfp_network` and `windows_read_deny` stay
   missing, the score stays at most 55, `sandbox.strict: true` and
   `require.run: full-boundary` still refuse a Windows run, and every Windows row stays
   preview. A score point is given only for what the system is shown to enforce.
2. The network path forward is an **opt-in, elevated setup** that installs a persistent
   WFP provider and sublayer owned by OpenMoat, with a block that matches a dedicated
   local account, and an `openmoat run` that starts the agent as that account. It needs a
   design of its own (the account's password storage, its profile, the project's access
   list for a second account) and the end-to-end tests on CI's `windows-latest` runner,
   which runs elevated, beside a test that an unelevated run still says what it lacks.
3. Read denial on Windows waits for the same account: an account that is not the person's
   reads only what the person's access lists grant it, which is the boundary a read deny
   needs; until then reads are the hook's, as `docs/SANDBOX.md` says.

## Consequences

- No change in behaviour, score or wording beyond pointing `docs/SANDBOX.md` and the run's
  network gap at this ADR.
- The proxy variables still route programs that honour them through the run's proxy; one
  that ignores them connects directly, as ADR-115 states.
- The next Windows step is decided: the dedicated account, set up once by an
  administrator, not a weaker filter that would show a score it does not earn.

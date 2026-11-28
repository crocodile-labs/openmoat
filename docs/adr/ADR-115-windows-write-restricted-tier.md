# ADR-115: A first Windows tier for `openmoat run`: a write-restricted token in a job object

Status: accepted, released as a preview in 0.26.0; the network and reads it leaves out are ADR-129's · Date: 2026-11-23 · Builds on ADR-018 (tiers), ADR-077 (full boundary),
ADR-083 (the state directory's access list), ADR-089 (the run's boundary record), ADR-105
(scrubbed environment), ADR-108 (protection score) · Numbered 115: 114 is taken by a change
open at the time of writing

## Context

On native Windows OpenMoat decided tool calls and enforced nothing: `openmoat run` refused
("no sandbox OpenMoat can generate"), so every Windows row of `docs/PROTECTION.md` was the
hook alone, where an allowed call runs with the person's permissions and a classifier
mistake is a bypass.

Two other agent products ship a Windows sandbox:

- **OpenAI's Codex** ([Building the Codex Windows sandbox](https://openai.com/index/building-codex-windows-sandbox/)).
  Its first, unelevated version starts commands under a *write-restricted token*: Windows
  checks a write twice, once against the person's SIDs and once against the token's
  restricting SIDs, and allows it only when both grant it. The restricting SIDs are
  `Everyone`, the logon session's SID and a synthetic `sandbox-write` SID, and setup grants
  that SID write on the working directory and the configured writable roots, with denies on
  `.git`, `.codex` and `.agents` inside it. Its network controls there were advisory (proxy
  variables pointing at a dead port), "not built to resist adversarial code". Its later,
  elevated version runs commands as dedicated local users and blocks the network with
  firewall rules for one of them; that needs administrator rights at setup. Codex rejected
  AppContainer ("the wrong shape" for open-ended developer work), Windows Sandbox (not on
  Home editions, and not the real checkout) and integrity labels (relabelling a workspace
  lets every low-integrity process write it).
- **Anthropic's sandbox runtime** has a Windows alpha that filters the network with the
  Windows Filtering Platform (WFP).

Microsoft documents the parts:
[`CreateRestrictedToken`](https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
(`WRITE_RESTRICTED`: the restricting SIDs are checked for write access only),
[restricted tokens](https://learn.microsoft.com/windows/win32/secauthz/restricted-tokens),
[`CreateProcessAsUserW`](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
(a restricted version of the caller's primary token needs no extra privilege),
[job objects](https://learn.microsoft.com/windows/win32/procthread/job-objects)
(`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; without `JOB_OBJECT_LIMIT_BREAKAWAY_OK` no process
leaves) and [AppContainer isolation](https://learn.microsoft.com/windows/win32/secauthz/appcontainer-isolation).

## Decision

1. **`openmoat run` on Windows starts the program under a write-restricted token, in a job
   object** (`commands/run/windows.rs`, the Win32 calls in `commands/run/windows/win32.rs`
   through `windows-sys`, already a dependency of the CLI on Windows since ADR-083; one
   feature, `Win32_System_JobObjects`, is added; the core stays dependency-free). The token
   is this process's, with `DISABLE_MAX_PRIVILEGE` and `WRITE_RESTRICTED`; its restricting
   SIDs are `Everyone`, the logon session's SID, a SID for the objects the agent creates
   (granted in the token's default access list, so it can write its own pipes) and one SID
   per write root. The tier is a Lightweight tier: there is no Isolated tier on Windows.
2. **Write roots get one inherited allow entry for their own SID** (read, write, run,
   delete; never `WRITE_DAC`, `WRITE_OWNER` or `FILE_DELETE_CHILD`). The roots are the
   policy's literal write trees (the project), the run's temp directory and `--write`
   paths, as for Landlock; a policy that allows every write, or a whole drive, is refused.
   The SID of a root is derived from its path (`S-1-5-21-…` from SHA-256), so the next run
   finds the entry and changes nothing; adding one makes Windows hand it to every file
   below, which takes time once in a large tree. The entries are kept: they name SIDs no
   account has. A root at or inside the state directory is refused (its list holds exactly
   two entries, ADR-083).
3. **Write denies inside a root that name a literal place get a deny entry** for the root's
   SID on that place (every write right), and a deny of `DELETE` on each folder between the
   root and it, so the folder cannot be renamed away and replaced. `.git`, `.moat`, the
   editors' and CI folders at the project's top are held this way. A place that does not
   exist when the run starts, a glob no single place stands for, and the same name deeper
   than the root's top stay the hook's; the run's report names them.
4. **Reads are not restricted, and that is stated.** A write-restricted token is checked
   against its restricting SIDs on writes only. Every read deny rule stays hook-only on
   Windows. AppContainer would restrict reads, but needs every readable place granted,
   which is the wrong shape for an agent that reads toolchains anywhere (Codex's finding).
5. **The network is not held by the operating system.** `HTTP_PROXY`, `HTTPS_PROXY` and
   `ALL_PROXY` point at the run's proxy, as elsewhere; a program that ignores them connects
   directly. The record's network mode is `proxy_variables`, with a `network` downgrade.
   `--netns=require` and `require.run: full-boundary` refuse on Windows. A WFP filter is
   future work.
6. **The agent starts suspended** (`CREATE_SUSPENDED`), inheriting only its three standard
   handles (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), is put in the job, and its own token
   (`IsTokenRestricted`) and job membership (`IsProcessInJob`) are read back before it runs
   an instruction. Those are the launch check: the boundary row is written, and anything not
   confirmed ends the job before the agent ran. When the agent exits, the job is ended, so
   nothing it started outlives the run.
7. **The protection score (ADR-108) on Windows** weighs `restricted_token` 45, `job_object`
   10, `wfp_network` 30 and `windows_read_deny` 15. The last two are not built, so a
   Windows run scores at most 55, and `sandbox.strict: true` refuses every Windows run, as
   it should: the number says how much of a full boundary is missing.
8. **No batch files.** `std::process::Command` cannot start a process under another token,
   so the tier builds the command line itself with the C runtime's quoting. `cmd.exe` reads
   a batch file's arguments by other rules, so `.bat` and `.cmd` programs (an npm shim) are
   refused with the reason; the agent's `.exe`, or `node` with the package's script, starts.
   For the same reason `openmoat mcp wrap` does not put servers under this tier by default
   (most start through `npx`); `--sandbox` still asks for it.
9. **The hook relay.** Under the token a hook can read the state directory and could not
   write the audit log, so on Windows the guard opens the lock for writing and relays its
   call to the run only when that is refused and its own token is restricted
   (`guard_relay/inside/windows.rs`); a variable or setting cannot make a token restricted.
10. **What is left out of this tier:** the tool-shell wrapper (ADR-075; tool commands keep
    the relay token, and the record says so), Windows' environment names compared without
    case in the scrubbed environment (done), and every row of `docs/PROTECTION.md` stays
    *preview* until a test runs a real agent under the tier.

## Consequences

- Windows gets an OS boundary for writes and the process tree, with an honest score of 55
  and every missing part named in `--print-boundary`, `doctor` and the audit log.
- Anything writable by `Everyone` stays writable to the agent, as in Codex's design.
- Reads of secrets, other agents' logins and OpenMoat's own state are the hook's alone on
  Windows; the network is held only for programs that honour the proxy variables.
- CI's `windows-latest` job runs the end-to-end tests that a write outside the project is
  refused, one inside works, a folder's access list outside cannot be widened, and the job
  ends what the program left running.

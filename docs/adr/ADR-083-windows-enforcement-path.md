# ADR-083: Windows enforcement: WSL2 and no-admin steps now, a native `openmoat run` after 1.0, never a driver

Status: accepted for phase 1 (decisions 1, 2, 5, 6 and 7, built); decisions 3 and 4 (the native backend) proposed until the spike's measurements below exist · Date: 2026-11-12 · Issues #135, #272 · Builds on ADR-018 (sandboxes from the IR), ADR-034 (`hook_only`), ADR-071 (state file modes), ADR-077 (full boundary)

## Context

On native Windows OpenMoat is hook only for Claude Code and Cursor; Codex's own Windows
sandbox gets OpenMoat's profile; `openmoat run` and `openmoat proxy install` refuse
([SANDBOX.md](../SANDBOX.md)). The workspace forbids `unsafe`, and every Win32 sandbox API
is foreign code.

What is reachable on Windows:

- Kernel-mode drivers (a minifilter, a WFP callout): "Windows will not load any new
  kernel-mode drivers which are not signed by the Dev Portal", which needs an EV certificate
  (<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later->).
- AppContainer and job objects: no driver, and no administrator for the profile
  (<https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer>,
  <https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>).
- Microsoft's MXC (`processcontainer`, Rust crate `mxc-sdk`): no tagged release, several
  backends marked experimental, Windows host filtering "backend-dependent"
  (<https://github.com/microsoft/mxc>, read 2026-11-10).
- WSL2 runs a Linux kernel, so OpenMoat's Linux tiers apply inside it.

Three things made native Windows weaker than it needs to be, each fixable without an
administrator and without `unsafe`:

1. **WSL is a way around the Windows rules.** OpenMoat's deny rules name Windows paths
   (`~/.ssh/**` is `C:/Users/me/.ssh/**` there). A command run inside a WSL distribution
   (`wsl cat ~/.ssh/id_rsa`) reads the distribution's own files, which no Windows path
   names, and reaches the Windows drives under `/mnt/c` beside them; the `\\wsl$` and
   `\\wsl.localhost` shares let a Windows program open the distribution's files directly.
   The classifier saw `wsl` as an unknown program and left it to the agent's own prompt.
2. **Codex's Windows sandbox has modes of different strength**, and OpenMoat did not say
   which runs. Codex's documentation (<https://learn.chatgpt.com/docs/windows/windows-sandbox.md>,
   read 2026-11-12): `[windows] sandbox = "mxc"`, `"elevated"` or `"unelevated"`, and
   `[features] prefer_mxc = true`; MXC and elevated enumerate deny-read globs when each
   sandboxed process starts; unelevated "doesn't support denied read paths" and "has weaker
   network isolation"; with no mode selected "Codex prefers `elevated`".
3. **The state directory had no access list of its own on Windows.** On Unix it is `0700`;
   on Windows it inherited whatever the folder above grants, which on a second drive's root
   includes a change right for `Authenticated Users`.

## Decision

1. **WSL2 is the supported path to OS confinement on Windows** until a native backend
   exists. `openmoat doctor` says so on native Windows when `wsl.exe` is installed, and says
   under WSL1 that `openmoat run` and the agents' sandboxes need WSL2 (WSL1's release is
   `4.4.0-<build>-Microsoft`; WSL detection inside Linux, `WSL_DISTRO_NAME` and the kernel
   release, already existed in `os_version.rs`).
2. **The `wsl-crossing` deny group** (default policy, `hook_only`). The classifier emits
   `@wsl <launcher>` for a command that runs a WSL launcher and `@wsl share` for one naming
   the WSL share; the group denies `@wsl *`, reads and writes of the share's paths, and reads
   of the launcher binaries in the system folders, so a copy under another name is denied.
   - Words are read as Win32 reads a path: either slash, any letter case, trailing dots and
     spaces dropped (`wsl.exe.`), an NTFS stream dropped (`wsl.exe::$DATA`), `.` and empty
     components dropped, `..` taken back; with or without `.exe`.
   - Launchers: `wsl`, `wslg`, `wslconfig` (also its 8.3 short name `wslcon~N`), the legacy
     `bash.exe` in `System32`, `Sysnative` or `SysWOW64` or under `WinSxS`, and the listed
     Microsoft Store distributions' own launchers (`ubuntu`, `ubuntu<version>` and
     `ubuntu~N`, `debian`, `kali`, `fedoraremix`, `opensuse-…`, `sles-…`, `oraclelinux…`,
     `almalinux…`). `wsl.exe`, `wslg.exe` and `bash.exe` fit 8.3 already, so they have no
     other short name; `System32` has none either.
   - Runner lines are read only when they are simple; this allow-list is the design.
     Chasing the PowerShell constructs that compute a program one at a time does not end
     (`$t::Start(…)`, `([type]'…')::Start`, `$ExecutionContext.InvokeCommand.InvokeScript`,
     `(New-Object -ComObject WScript.Shell).Run`), so a line is held for review
     (`@opaque-code <runner>`, rule `opaque-code`) unless every part of it is simple, and it
     fails toward review by construction (`shell/wsl/runner/simple.rs`). A PowerShell line
     (`powershell`/`pwsh` and their `-Command` bodies, and any runner line that starts
     PowerShell) is simple when it holds only bare words, options (`-Name`,
     `-Name:value`), paths, single-quoted strings, double-quoted strings without `$` or a
     backquote, the separators `;`, `|`, `&&`, `||` and a line break, and redirects to files.
     Anything else is not: `$` outside a single-quoted string, `(`, `)`, `[`, `]`, `{`, `}`,
     `::`, `@`, a backquote, a lone `&` or a leading `.` (the call operators), the operators
     `-join`, `-replace`, `-split` (and their `c`/`i` forms) and `-f` after a quoted string,
     `New-Object`, `Add-Type`, `iex`, `Invoke-Expression`. A `cmd` line (`cmd`, `start`,
     `forfiles`, and any runner line that starts `cmd`) is simple when it has no `^`, `%` or
     `!`, no parenthesis outside double quotes and no `for` or `call`. The checks below sit
     on top of the allow-list and still apply to simple lines.
   - In a simple line, the program word of each
     segment counts (after `&`, `|`, `;`, a parenthesis, a brace, `call` or `.`, and after
     the shell's own options), so `cmd /c docker run ubuntu` is not a crossing. The
     options are read from tables: PowerShell's (an option that takes a value, such as
     `-ExecutionPolicy`, `-WindowStyle`, `-Version`, `-File`, skips it, by full name, short
     name or unique prefix; an unknown or ambiguous one makes the line opaque), `cmd`'s
     (`/c`, `/k`, `/r` also with the program glued on, `/cwsl`, and Git Bash's `//c`),
     `start`'s and `Start-Process`'s (`-FilePath` names the program, `-ArgumentList` its
     arguments). `cmd` reads only `"` as a quote, PowerShell `'` too; a `'` or backquote
     around a `cmd` program (`for /f %i in ('wsl ls')`) is dropped. A bare `bash`, or one in
     the system folders, is a launcher there, because Windows' search finds
     `System32\bash.exe` first; another `bash.exe` (Git's) is not. A launching program
     (`start`, `Start-Process`, `saps`, `explorer`, `wt`, `runas`, `conhost`, `Invoke-Item`)
     names its program in its first word that is not an option.
   - The backstop. Parsing `cmd` and PowerShell exactly keeps losing, so a runner line in
     which `wsl`, `wslg`, `wslconfig` or `bash` (also `.exe`, as Win32 reads a component)
     stands as a whole word anywhere, quoted or not, is held for review (`opaque-code`)
     whatever the parse found; the deny stays for what the parse identifies. So `cmd /c
     echo wsl`, a `Start-Process code -ArgumentList bash` and a Git `bash.exe` by path in a
     `cmd` line need review.
   - Links: `fsutil hardlink create`, `mklink /H` and `New-Item -ItemType HardLink` whose
     target is a launcher are denied as that launcher, and reading the launcher binaries
     is denied (the system folders, `WinSxS`, the Store WSL's `C:\Program Files\WSL`).
     These paths assume Windows on `C:`.
   - `./bash.exe` runs the file in the working directory: a launcher where that is a
     system folder (`cd /c/Windows/System32 && ./bash.exe`), and held for review where the
     directory is not known.
   - The share: a word starting with `\\` or `//` (also after `file:`, an option's `=`, or
     the `:` of an option such as `-Path:\\wsl$\x`)
     with `wsl$` or `wsl.localhost` as any component, which covers `\\wsl$\…`, the
     `\\?\UNC\`, `\\.\UNC\` and `\\?\GLOBALROOT\Device\Mup\` forms; a word naming it is
     enough (`net use Z: \\wsl$\Ubuntu` maps a drive, after which no path names WSL).
   - A runner line built at run time cannot be read, so it is held for review
     (`@opaque-code <runner>`, rule `opaque-code`), not allowed: a program word with a `cmd`
     escape (`^`), a variable (`%x%`, `!x!`), a joined string (`'ws'+'l'`) or a PowerShell
     escape; after a call operator (`&`, `.`) any `$` or a parenthesis (`& (gcm wsl)`,
     `& (-join …)`); a `$( … )` inside a PowerShell double-quoted string; `iex`,
     `Invoke-Expression`, `icm`, `Invoke-Command`, `gcm`, `Get-Command`, `[scriptblock]`;
     `-EncodedCommand` (any prefix PowerShell accepts, and `-ec`) and `-Command -`; a UNC
     word built the same ways (`\\ws%x%l$`); and every `wt` line, whose profiles may start a
     distribution. So are lines that choose their program in other ways: a `>` or `>>` into
     a script file (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.wsf`, …), which the line may run
     next; `forfiles`
     (also from Git Bash) with a `/m` mask or an `@path`/`@file` in its command; a launching
     program's program word with a `$` or a parenthesis (`saps $a`, `Start-Process -FilePath
     $a`, `saps (…)`); and a `*` or `?` in a program word or in any path under
     `Windows\` or `Program Files\WSL\`, whose match the literal names of the read deny miss.
     What such a line runs is not decided, only held.
   - Limits, stated plainly: a launcher started through a name the line does not show (a
     shortcut, a `.lnk`, a scheduled task, a renamed copy made outside the hook, an App
     Execution Alias of a distribution not listed), a script file the agent wrote in an
     earlier call and runs now (`cmd /c build.cmd` runs whatever `build.cmd` holds; only a
     script the same line writes is held), and a bare `bash` outside a runner line are not
     recognised. The agents' own PowerShell tools (Claude Code's `PowerShell` tool) are not
     parsed at all: their calls are decided by the rest of the policy and the hook's
     unparseable handling, not by this rule.
   - A bare `bash` outside a runner line is not a launcher: in Git Bash, where Claude Code
     runs commands on Windows, it is Git's own bash, and its `-c` code is classified as any
     shell's.
   - `hook_only`: the host sandboxes grant no path there, and their file formats were not
     checked for UNC paths.
3. **No kernel driver, ever.** No minifilter, no WFP callout. Firewall rules without a
   callout only as an optional, person-run, administrator step if a native backend needs
   them, recorded and removed by `uninstall`.
4. **A native `openmoat run` on Windows after 1.0**, chosen by the spike below: MXC if it has
   a tagged release that enforces denied paths and proxy-only network on Windows (compile
   the IR to an MXC policy, as Landlock rules are compiled today); otherwise AppContainer +
   job object in a separate crate whose `unsafe` an ADR allows; neither: keep refusing and
   point to WSL2. Every ACE such a backend sets on the person's files is recorded, shown
   before it is set, and removed at exit and by `uninstall`; a crash leaves a record `doctor`
   repairs.
5. **Codex's Windows sandbox mode is a host fact** (`SandboxSpec::windows_modes`, a
   `WindowsSandboxReader` in `host/codex/windows_sandbox.rs`). `openmoat doctor` on Windows
   reads Codex's `config.toml` and shows one row: `mxc` or `elevated` hold OpenMoat's read
   denies (a passing row); `unelevated` does not, so they hold only through the hook (a
   warning naming the stronger setting); no mode, `prefer_mxc` alone or an undocumented
   value cannot be told (a note). A managed `requirements.toml` that narrows the modes
   (`allow_mxc`, `allowed_sandbox_implementations`) is not read yet.
6. **The state directory's access list.** On Windows `Home::ensure` (`openmoat init`) gives
   the directory exactly two entries, full control for the person's account and `SYSTEM`,
   handed on to everything created inside: `<SystemRoot>\System32\icacls.exe <dir>
   /inheritance:r /grant:r *<you>:(OI)(CI)F *S-1-5-18:(OI)(CI)F`, then `icacls <dir> /remove
   *<sid>` for every other account an explicit entry names and `/remove:d` for a deny entry
   naming the person or `SYSTEM`
   (<https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls>;
   a folder's owner may change its list without being an administrator). A new directory
   has only inherited entries, which `/inheritance:r` drops (`init` tells one it made
   itself by `create_dir`, which fails when anything is already there, so a folder another
   account made a moment before is read like any existing one); an existing one is read first
   (owner and DACL in SDDL, through Windows PowerShell's .NET
   `Directory.GetAccessControl`, so no account name is translated), and one another account
   owns is refused: OpenMoat does not take it over. Every program runs from
   `%SystemRoot%\System32` by absolute path, never from the search path. A drive without
   access lists (FAT, exFAT) fails with that said, and MOAT_HOME on an NTFS drive as the fix.
   `doctor` reads the owner and list back and shows a problem row for another owner or any
   other account that may change it or what is created inside, a warning for one that may
   read it or a list still inherited, each with `openmoat init` and the exact `icacls` calls
   that fix it. Administrators count as trusted: their group applies only in an elevated
   process, which can take ownership of the folder anyway. A state file given a list of its
   own is not read.
7. **What the access list cannot do is said, not hidden.** The agent runs as the person, an
   account may always change the list of a folder it owns, and OpenMoat itself must write
   there, so no list holds against the person's own account. `doctor` prints that beside the
   row, and the docs say the hook's `kernel-self` rule and a sandbox are what keep the agent
   out.

## What this must never do

- Claim confinement on native Windows before a backend passes EVIDENCE.md fixtures on a
  Windows CI runner.
- Fall back silently: `openmoat run` on Windows refuses (exit 64) until the backend exists,
  and `require.run: full-boundary` keeps refusing.
- Put Windows host facts outside `openmoat-hosts` (Codex's keys are in `host/codex`).
- Say the state directory's access list keeps the agent out.

## AppContainer vs MXC: the spike

No product code; this is the comparison and the measurement plan for decision 4. Nothing
below has been run: the measurements need a Windows 11 24H2 machine, and GitHub's hosted
Windows runners are Windows Server.

| | AppContainer + job object, our own crate | MXC `processcontainer` through `mxc-sdk` |
|---|---|---|
| Files | deny by default; reads and writes granted by an ACE for the container's SID on the project, the read roots and the agent's install folder; a deny ACE inside a grant covers only files that exist when it is set | a policy of read-only, read-write and denied paths; denied paths on Windows not supported by the README read on 2026-11-10 |
| Changes to the person's files | ours: every ACE recorded, shown, removed, repaired after a crash | MXC's own, not documented |
| Network | by capability: none, or every internet host; loopback (OpenMoat's proxy and relay) needs an exemption that is a machine setting, likely an administrator's | routing to a proxy; host allow and block lists "backend-dependent" on Windows |
| Process tree | job object with `KILL_ON_JOB_CLOSE`; a WMI `Win32_Process.Create` child escapes the job | the engine's |
| `unsafe` | every call, in a separate crate an ADR allows it in | none in OpenMoat; the crate's own |
| Maturity | Windows APIs since Windows 8 | no tagged release; Codex's MXC mode and GitHub Copilot CLI use it (secondary sources) |
| Windows versions | Windows 10 and later | Windows 11 24H2 and later |

Measurements that decide it, each on Claude Code and Codex with their own sandboxes off:

1. Does the agent start and finish a task (Node, git, npm, `%APPDATA%`, the registry)?
2. Time to grant the project on a 100 000-file tree, and to remove the grants.
3. Does loopback to `openmoat proxy` work without an administrator?
4. Is a file under a denied path unreadable, including one created after start?
5. Does a child started through WMI or a scheduled task escape?

Reading of the evidence so far: MXC is the smaller and better-maintained route, but it does
not yet enforce denied paths or per-host network on Windows, so it does not meet decision
4's bar; AppContainer meets the file part only with ACEs on the person's files, and its
network part likely needs an administrator. Until a measured run says otherwise, decision 4
stays "keep refusing, point to WSL2".

## Consequences

- An agent on native Windows can no longer reach a WSL distribution's files or commands
  through its hook-checked calls; a person who wants an agent in WSL runs the agent there,
  where the Linux protections apply.
- False positives: an agent cannot run `wsl --list` or name the share in any word; a
  runner line built at run time, or one that merely names `wsl` or `bash` (`cmd /c echo
  wsl`, `cmd /c echo bash`), needs review even when it runs nothing of WSL's. On Windows any
  PowerShell code beyond simple commands needs review: a variable (`echo $Env:HOME`), a
  .NET call (`[math]::Round(1.5)`, `[System.IO.Path]::Combine('a','b')`,
  `[Environment]::GetEnvironmentVariable('PATH')`), a script block (`gci | ? { $_ }`).
  That is the price of failing toward review: PowerShell can compute and start any program
  from text, and a parser that reads only some of its constructs leaves the rest open. So
  does a `cmd` line with `%`, `!`, `^`, a block, `for` or `call` (`echo %PATH% > out.txt`),
  and a wildcard in a path under `Windows\` (`Get-ChildItem C:\Windows\Temp\*.log`).
  Simple build commands stay with the agent's own prompt (`cmd /c build.cmd`,
  `cmd /c gradlew.bat build`, `powershell -c .\build.ps1`). A distribution installed
  without a Store launcher is reached only through `wsl -d`, which is denied anyway; a
  launcher of a distribution not listed above is not recognised.
- Not covered: the reverse direction (a command inside WSL starting `cmd.exe` or any `.exe`
  under `/mnt/c` through interop), and the Windows profile (`/mnt/c/Users/<name>/` secrets,
  `.wslconfig`, the Startup folder) as seen from inside WSL. Both are phase-1 items of the
  plan below still to build, with WSL2 evidence from a real machine.
- `openmoat init` on Windows starts `whoami` and `icacls` for a new state directory, and
  Windows PowerShell once more for an existing one; `doctor` starts PowerShell once.
- Only Windows CI runs the code that sets and reads the list; its parsing is tested on every
  system.

## Step plan

1. WSL guidance in `doctor` (built). `status` and the home screen still to follow.
2. `wsl-crossing` (built). The Windows profile seen from inside WSL: to build, with attack
   and benign fixtures.
3. Codex's mode in `doctor` and the state directory's access list (built). `sandbox show`
   listing the read denies as wider under `unelevated`: to build.
4. The spike's measurements above, on a Windows 11 24H2 machine; an amendment records the
   choice.
5. A native backend after 1.0, split per the chosen option: process tree, files, network to
   the proxy only, EVIDENCE.md Windows rows.
6. `openmoat proxy install` on Windows as a per-user scheduled task at logon (#272).

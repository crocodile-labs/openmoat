# ADR-094: The approvals listener as a user service, and credentials read without echo

Status: accepted · Date: 2026-11-13 · Builds on ADR-078 (remote approvals), ADR-020 and
#272 (`openmoat proxy install`) · Numbered 094: 092 and 093 may be taken by branches open
at the time of writing

## Context

ADR-078 has `openmoat approvals listen` running "at a terminal of the person's own":
answers arrive only while it runs, so closing the terminal, logging out or a reboot
silently turns remote approval off, and requests expire unanswered. Its "Next steps"
named a service unit like `openmoat proxy install`.

`listen` is a person-only command: it refuses without a terminal and with an agent or
`openmoat run` among its ancestors (`terminal::refuse_agent`), and the default policy's
`kernel-self` denies every `openmoat approvals` command an agent tries. A service has no
terminal, so a service-started listener cannot pass the terminal check as it is.

Separately, `openmoat approvals connect telegram` asked for the bot token with an
ordinary line read from `/dev/tty`: the terminal echoed the token as it was pasted, so it
stayed on screen and in the terminal's scrollback.

## Decision 1: a credential is read with the terminal's echo off

`terminal::read_secret` reads one line from the controlling terminal with `ECHO` cleared
(through `rustix::termios`, already in the build; only its `termios` feature is new),
`ECHONL` set so Enter still moves to the next line, and the terminal's settings put back
on every path out. While it reads, `ISIG` is off and the interrupt character is the
terminal's extra end-of-line character (`VEOL`): Ctrl-C ends the read as "cancelled"
instead of killing the process with echo off. It refuses when stdin is not a terminal (a
piped secret sits in a script or a shell history); `--credential-file` is the way to
give one from a file. On Windows, where this crate makes no console-mode calls, it
refuses and names the file option. Nothing prints what was read; errors about the line
(empty, too long, not text) never contain it.

`approvals connect` is the only prompt in the CLI that reads a secret: `openmoat secret
add` names where a secret is read from (a variable, a file, the keychain, a command) and
never takes the value; `openmoat proxy ca init` asks only yes or no; audit delivery reads
its tokens from files. Any later secret prompt uses `read_secret`.

## Decision 2: `openmoat approvals install` / `uninstall`

Named as `openmoat proxy install` is. `install` is a person's command (terminal, no agent
ancestor), needs a connected channel, and writes, through the same service code as the
proxy (`commands/service/`, now driven by a `Job` per service):

- macOS: `~/Library/LaunchAgents/dev.openmoat.approvals.plist`, `RunAtLoad`,
  `KeepAlive = {SuccessfulExit = false}`, `Umask` 077, stdout and stderr to
  `~/.moat/logs/approvals.out.log` and `approvals.err.log`;
- Linux: `~/.config/systemd/user/openmoat-approvals.service`, enabled for
  `default.target`, `Restart=on-failure` with the proxy's start limit, `UMask=0077`,
  `StandardOutput=append:` and `StandardError=append:` to the same two files (not the
  journal, which members of `systemd-journal` can read);
- both: the program is the pinned binary the hooks run (`install::hook_binary`) with
  `approvals listen --service`, and `MOAT_HOME` is the only variable. The file is
  owner-only, and both log files are created owner-only before the service manager opens
  them (launchd would create a missing one with its own umask).

`uninstall` stops and removes it; `openmoat uninstall` removes it with the hooks, as it
does the proxy's. Windows refuses, as for the proxy. `approvals status` and `doctor`
report its state and every way the installed file differs from what `install` writes
(the proxy's read-back check, ADR-020/#272), with the proxy's file bytes unchanged.

## Decision 3: how the service's listener runs without a terminal

What `listen` can do decides what its launch checks must protect. It sends signed
requests, polls the channel's server over TLS, and writes a signed answer only for a
reply the server delivered from an approver a person allowed, to a button OpenMoat sent.
It grants nothing a person has not already granted. What a launcher could gain from
starting it is what it can steer: the process's memory (the token and the key), the
libraries it loads, and the TLS roots it trusts.

The terminal check was never the barrier for those: an agent able to run code can give a
program a pseudo-terminal (Python's `pty`), and the policy's deny of the pty wrappers is a
hook check. The barriers are the ancestry check (an agent cannot remove itself from a
child's ancestors; on Linux, `ptrace_scope` 1 allows attaching only to descendants), the
policy, and the OS sandboxes' read deny on `~/.moat/remote`, which every child of a
sandboxed agent inherits.

So `listen --service` keeps every barrier and replaces the terminal check with checks
of the launch itself. In order:

1. `refuse_agent`, unchanged: no agent and no `openmoat run` among its ancestors.
2. The environment steers nothing: refused when `SSL_CERT_FILE`, `SSL_CERT_DIR` (which
   `rustls-native-certs` reads), `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT` or any
   `DYLD_*` is set. Nothing sets them for the service but a change to the user's service
   environment (`launchctl setenv`, `systemctl --user set-environment`). A person's
   terminal `listen` is not checked this way: their shell is theirs.
3. The service file is there and reads back as exactly what `install` writes for this
   binary and state directory, owner-only (the read-back check).
4. The service manager started it: on macOS its parent is launchd (pid 1) and
   `XPC_SERVICE_NAME` is the job's label; on Linux `INVOCATION_ID` is set and its control
   group is the unit's.

Checks 2 to 4 are consistency checks, not a boundary: a process of the same user can
imitate what they read (a double fork reparents to pid 1, a variable can be set, a
same-user process can move itself between its own control groups). They catch a changed
service environment or file and a listener started by hand with `--service`; they do not
claim more. What they leave open is what ADR-078 already accepts for every person-only
command: code an agent runs outside every sandbox, as the same user, can do what that
user can.

`kernel-self` denies `openmoat approvals install`, `uninstall` and `listen --service` as it
denies every `openmoat approvals` command.

## Decision 4: one listener, and a service that waits

Two listeners would each send every request and race for the channel's replies. `listen`
takes an exclusive lock on `~/.moat/remote/listen.lock` (`File::try_lock`); a person's
second `listen` is refused with the reason, the service waits for the lock. When the
channel is disconnected or another is connected, a person's listener stops as before;
the service logs the reason once and looks again every 30 seconds, so `disconnect` and
`connect` do not need the service reinstalled and a missing channel is not a restart
loop.

On Linux the listener makes itself non-dumpable (`PR_SET_DUMPABLE` 0), so another
process of the same user cannot attach to it or read its memory through `/proc` even
where `ptrace_scope` is 0. macOS has no such switch without `unsafe`; there another
process gets the listener's task port only with a debugger's authorization.

## Consequences

- Remote approval keeps working after the terminal closes and after login, once a person
  runs `openmoat approvals install`.
- The log names approvers, request codes and the agent's sessions; it is owner-only under
  `~/.moat/logs`, which the default policy already keeps agents from writing. It is
  appended to and not rotated.
- A service started with a steered environment does not run; the person unsets the
  variable in the service environment, or runs `listen` in a terminal.
- `commands/service/` describes each service as a `Job`; a third one is a constant.

## Threat model additions

| Threat | What stops it | Test |
|---|---|---|
| A pasted bot token stays on screen | echo off while it is read; no output contains it | `terminal::secret::tests::a_secret_typed_at_a_terminal_is_read_and_never_shown`; e2e `approvals_service::a_credential_typed_at_connect_is_never_shown` |
| Ctrl-C at the token prompt leaves the terminal blind | the interrupt key ends the read; the settings are put back | `terminal::secret::tests::ctrl_c_cancels_the_read_and_puts_the_terminal_back` |
| A token piped in from a script | refused unless stdin is a terminal | `terminal::secret::tests::piped_input_is_never_read_as_a_secret` |
| An agent installs or runs the listener service | `kernel-self`; `install` needs a person; `--service` keeps the ancestry check | e2e `approvals_service::an_agent_cannot_install_or_run_the_listener_service` |
| The service file changed to run something else or with more variables | `--service` refuses a file that does not read back; `status` and `doctor` name the change | e2e `approvals_service::install_writes_the_listener_service_owner_only_and_uninstall_removes_it` |
| The service environment changed to trust another CA or load a library | `--service` refuses to start | the same e2e; `commands::approvals::listen::tests` |
| Another user reads the service's log | `Umask`/`UMask` 077 and log files created owner-only | plist and unit tests; the same e2e |

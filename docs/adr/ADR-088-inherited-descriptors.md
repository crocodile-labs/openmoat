# ADR-088: Descriptors `openmoat run` inherited are closed to the sandbox

Status: accepted · Date: 2026-11-12 · Builds on ADR-018 (OS sandbox tiers), ADR-080
(the Isolated tier by default on Linux), ADR-046 (`unsafe` in `openmoat-wasm`)

## Context

A process starts with whatever descriptors its parent left open without
close-on-exec. A shell does that for `exec 3<file`, an IDE or a CI runner for pipes
and files it hands to its children, and some launchers leak them by mistake. Each such
descriptor passes through every `exec` that follows, so `openmoat run` would hand it to
the agent and to every command the agent runs.

The sandboxes do not catch it. Landlock checks a path when it is opened; a descriptor
opened before `restrict_self` keeps whatever access it was opened with. Seatbelt checks
operations on paths and sockets; a descriptor that is already open reads and writes
without a path. bubblewrap passes every open descriptor of its own on to the program it
starts. A descriptor on `~/.ssh/id_rsa`, on a socket to a local service, or on a
directory outside the grants (`openat` relative to it) would go around every rule of
the policy.

Rust's standard library opens everything it creates with close-on-exec, but it never
changes the descriptors the process started with. Nothing in OpenMoat did.

## Decision

1. **Before the sandboxed program starts, every descriptor from 3 up is marked
   close-on-exec.** Standard input, output and error (0, 1, 2) stay: they are the
   agent's terminal or the pipes its host gave it. OpenMoat keeps using every descriptor
   it holds; the flag only takes effect at `exec`.
2. **Where.** In each tier's `Confined::status`, the one step every start goes through:
   the Lightweight tier on Linux (before the Landlock rules and seccomp filter apply,
   so the fallback below can still read `/proc`), bubblewrap's start for the Isolated
   tier and for the Lightweight tier's network namespace, `openmoat isolated` inside
   bubblewrap before it starts the agent, and `sandbox-exec` on macOS. One module,
   `commands/run/inherited.rs`, does it for both systems.
3. **How.** On Linux, `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)` (Linux 5.11 and later):
   one system call, no listing. Where it fails (an older kernel answers `ENOSYS` or
   `EINVAL`, a container's seccomp profile may answer `EPERM`), and on macOS, which has
   no `close_range`, the descriptors listed in `/proc/self/fd`, else `/dev/fd`, are each
   marked with `fcntl(F_SETFD)`. A descriptor that is gone by the time it is marked
   (`EBADF`: the listing's own, or one another thread closed) is skipped; a closed
   descriptor cannot reach the agent.
4. **Fail closed.** When neither `close_range` nor a listing works, or marking a listed
   descriptor fails other than with `EBADF`, `openmoat run` refuses to start the agent
   and says why. It does not start it with descriptors it could not check.
5. **Passed on purpose: none.** The proxy and the guard relay are reached by address
   (the environment names them), bubblewrap gets every argument on its command line and
   `sandbox-exec` its profile with `-p`. A descriptor OpenMoat hands to the sandbox in a
   later change must be named in `inherited.rs` and left out of the sweep explicitly.
6. **`unsafe`, in one file.** Neither the standard library nor rustix marks a
   descriptor by number without a borrow the code cannot prove (rustix needs a
   `BorrowedFd`, whose contract is that the descriptor stays open, which another thread
   could break), and neither wraps `close_range` with this flag. `openmoat-cli`'s
   `unsafe_code` lint is `deny` instead of the workspace's `forbid`, so
   `inherited.rs` alone can `#[expect]` it for three calls into `libc` that take and
   return integers (`syscall(SYS_close_range, …)`, `fcntl(F_GETFD)`, `fcntl(F_SETFD)`),
   each with a `SAFETY` comment. `openmoat-core`'s architecture test lists the files
   that may name the lint (this one and `openmoat-wasm`'s exports) and fails on any
   other, in sources, tests, benches, examples and `build.rs`; it fails too unless the
   workspace's level is `forbid` and every crate takes it or sets `forbid` itself, with
   `deny` only in a crate that owns a listed file, and when a listed file no longer
   names the lint, so the list only shrinks. `libc` moves from a Linux-only to a Unix dependency of
   `openmoat-cli`; it was already built on macOS through rustix and getrandom.

## Paths that do not sweep, and why

- **The tool-shell wrapper (ADR-075).** It runs inside the agent's sandbox and starts
  what the agent's host asked for; whatever it holds came from the agent, which could
  pass it on anyway.
- **An MCP server without `--sandbox`, a `command` secret source (ADR-087), `git`,
  `ps`, `launchctl` and the other programs OpenMoat runs for itself.** None of them is
  in a sandbox, so there is no boundary for a descriptor to cross. Under `openmoat run`
  the sweep has marked the whole process already, so the secret source's program, which
  the run's proxy starts later, gets none of the launcher's descriptors either. An MCP
  server with `--sandbox` starts through `openmoat run` and is swept there.
- **Windows.** `openmoat run` refuses there; the standard library starts children
  without inheriting handles except the standard ones it passes.

## Consequences

- A file, socket or directory the launcher left open no longer reaches the agent: a
  read through it fails with `EBADF`. The end-to-end tests open a denied file on
  descriptors 3 and 42 in a `bash` launcher and read both from inside, in the
  Lightweight tier on Linux and macOS and the Isolated tier on Linux, with a control
  run without `openmoat run` that does read them.
- A workflow that relied on passing a descriptor into `openmoat run` (a pipe on 3 for a
  build tool's job server, say) no longer gets it. Such a descriptor reached a sandbox
  that could not check it; the agent's standard streams are unchanged.
- Process substitution no longer reaches the program: in
  `openmoat run -- tool <(cmd)` the shell passes `tool` the path `/dev/fd/63` and keeps
  the pipe open on descriptor 63, which is now closed at `exec`, so opening the path
  inside fails (`EBADF` on macOS; `ENOENT` on Linux, where it is a `/proc` link). Write
  the output to a file in the project first (`cmd > input.txt; openmoat run -- tool
  input.txt`), or pipe it on standard input (`cmd | openmoat run -- tool -`).
- Another thread that opens a descriptor without close-on-exec after the sweep would
  pass it on. OpenMoat's threads open everything through the standard library, which
  sets the flag.
- `openmoat-cli` holds `unsafe` code, in one file, for the first time.

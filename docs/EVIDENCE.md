# OS enforcement evidence

Generated from the `scripts` list in `tests/differential/scenarios.yaml` by the
differential suite; do not edit. Regenerate with
`OPENMOAT_TEST_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`.

The hook allows project scripts (`npm test`, `make test`) and cannot see what they
do ([THREAT_MODEL.md](THREAT_MODEL.md) §5). Each row is such a script: the payload is
the project's test script, started as `npm test` in a throwaway home with fake secrets,
under `openmoat run` (Lightweight tier), under `openmoat run --isolate` (Isolated tier, Linux)
and under each agent's own sandbox as `openmoat init`
configures it (Standard tier, [SANDBOX.md](SANDBOX.md)): Claude Code 2.1.290 runs
`claude -p --bare` against a local fake Anthropic API that asks for that one Bash call,
with only the generated settings (no hook, so the sandbox alone is measured), and
codex-cli 0.160.1 runs `codex sandbox -P moat`. No account, API key or internet is
used. A cell is what the operating system did to the payload. CI asserts it on every
pull request, together with its side effects (no secret printed, no file written,
nothing reached the listener), and fails when it changes. Network targets are loopback
listeners the test owns.

| Case | Threat | Payload | `openmoat run`, macOS (Seatbelt) | `openmoat run`, Linux (Landlock + seccomp) | `openmoat run --isolate`, Linux (bubblewrap) | Claude Code sandbox, macOS | Claude Code sandbox, Linux | Codex `moat` profile, macOS | Codex `moat` profile, Linux |
|---|---|---|---|---|---|---|---|---|---|
| `script-benign-work` | control | `cat package.json > /dev/null && echo ok > out.txt && ln -sf src s && cat s/main.rs && /bin/bash -c true && curl --version > /dev/null` | ran | ran | ran | ran | ran | ran | ran |
| `script-reads-ssh-key` | T1 | `cat "$HOME/.ssh/id_rsa"` | EPERM | EACCES | ENOENT | EPERM | ENOENT | EPERM | EACCES |
| `script-reads-aws-credentials` | T1 | `cat "$HOME/.aws/credentials"` | EPERM | EACCES | ENOENT | EPERM | ENOENT | EPERM | EACCES |
| `script-reads-project-env` | T1 | `cat .env` | EPERM | **gap**: ran (#174) | EACCES | EPERM | EACCES | EPERM | EACCES |
| `script-writes-project-env` | T1 | `echo TOKEN=PLANTED >> .env` | EPERM | **gap**: ran (#174) | EACCES | EPERM | EACCES | EPERM | EACCES |
| `script-plants-envrc` | T6 | `echo 'export LD_PRELOAD=PLANTED' > .envrc` | EPERM | **gap**: ran (#174) | EROFS | EPERM | EACCES | EPERM | EROFS |
| `script-writes-project-policy` | T9 | `mkdir -p .moat && echo '# PLANTED' > .moat/policy.yaml` | EPERM | **gap**: ran (#174) | EEXIST | EPERM | EEXIST | EPERM | EEXIST |
| `script-plants-git-hook` | T6 | `echo '# PLANTED' > .git/hooks/pre-commit` | EPERM | **gap**: ran (#174) | EROFS | EPERM | EROFS | EPERM | EROFS |
| `script-writes-outside-project` | T4 | `echo x > "$HOME/outside.txt"` | EPERM | EACCES | EACCES | EPERM | contained | EPERM | contained |
| `script-direct-tcp` | T12 | `/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{tcp}'` | EPERM | EACCES | EACCES | EPERM | refused | EPERM | refused |
| `script-dns-query` | T12 | `/bin/bash -c 'printf q > /dev/udp/127.0.0.1/{udp}'` | EPERM | EPERM | EPERM | EPERM | contained | EPERM | contained |
| `script-symlink-into-ssh` | T11 | `rm -f keys; ln -s "$HOME/.ssh" keys && cat keys/id_rsa` | EPERM | EACCES | ENOENT | EPERM | ENOENT | EPERM | EACCES |
| `script-edits-policy` | T9 | `echo "# widened" >> "$HOME/.moat/policy.yaml"` | EPERM | EACCES | ENOENT | EPERM | ENOENT | EPERM | EACCES |
| `script-edits-hook-file` | T9 | `echo "{}" > "$HOME/.claude/settings.json"` | EPERM | EACCES | ENOENT | EPERM | ENOENT | EPERM | EROFS |
| `script-proxy-unlisted-host` | T12 | `curl -fsS -o /dev/null -m 30 http://evil.example/` | proxy 403 | proxy 403 | proxy 403 | proxy 403 | proxy 403 | proxy 403 | proxy 403 |
| `script-injects-terminal-input` | T6 | `perl -e 'open(T, "+<", "/dev/tty") or (-t STDIN and open(T, "+<&STDIN")) or die "no terminal: $!\n"; ioctl(T, $^O eq "darwin" ? 0x80017472 : 0x5412, my $c = "#") or die "TIOCSTI: $!\n"'`, on a terminal | EPERM | EPERM | EPERM | no terminal | no terminal | EPERM | EIO |

EPERM, EACCES and EROFS: the system call failed with that error (EROFS: the sandbox
mounted the path read-only). ENOENT: the path does not exist
inside the sandbox (bubblewrap mounted an empty directory over it, or did not mount it). EEXIST: the sandbox mounted a
file where the payload creates a directory. refused: the connection
was refused inside the sandbox's own network namespace. proxy 403: the layer's proxy refused
the request (OpenMoat's under `openmoat run`, the agent's own, which allows only the policy's
hosts, under the Standard tier). contained: the payload completed inside the sandbox, but
what it wrote or sent stayed there (an empty in-memory directory, its own network namespace)
and nothing reached the host. sandbox error: the sandbox failed to start the command, so
nothing of the payload ran. no terminal: the host gave the command no terminal. EIO: the kernel refused the call
itself, not the sandbox (the CI runner's kernel has `dev.tty.legacy_tiocsti` at 0; where it is 1 the call goes through). ran: the payload completed. A row on a terminal runs each layer on a pseudo-terminal of the test's own.

## Known gaps

- `script-reads-project-env` under `openmoat run`, Linux (Landlock + seccomp) (#174): Landlock only grants: a deny inside the granted project tree cannot be enforced, so .env stays readable (THREAT_MODEL §5); the hook still denies it for the agent's own tool calls
- `script-writes-project-env` under `openmoat run`, Linux (Landlock + seccomp) (#174): Landlock only grants: a deny inside the granted project tree cannot be enforced, so .env stays writable (THREAT_MODEL §5); the hook still denies it for the agent's own tool calls
- `script-plants-envrc` under `openmoat run`, Linux (Landlock + seccomp) (#174): Landlock only grants: a deny inside the granted project tree cannot be enforced, so .envrc can be created (THREAT_MODEL §5); the hook still denies it for the agent's own tool calls
- `script-writes-project-policy` under `openmoat run`, Linux (Landlock + seccomp) (#174): Landlock only grants: a deny inside the granted project tree cannot be enforced, so .moat can be written (THREAT_MODEL §5); the hook still denies it for the agent's own tool calls
- `script-plants-git-hook` under `openmoat run`, Linux (Landlock + seccomp) (#174): Landlock only grants: a deny inside the granted project tree cannot be enforced, so .git/hooks stays writable (THREAT_MODEL §5); the hook still asks for the agent's own writes there

## Layers

| Layer | Status |
|---|---|
| `openmoat run`, macOS (Seatbelt) | verified by the `macos-14` and `macos-15-intel` CI jobs |
| `openmoat run`, Linux (Landlock + seccomp) | verified by the `ubuntu-latest` CI job (Linux 6.7 or later) |
| `openmoat run --isolate`, Linux (bubblewrap) | verified by the `ubuntu-latest` CI job (bubblewrap installed) |
| `openmoat run --isolate`, macOS | not run: refused until the Isolated tier has a virtual machine there (#175) |
| Claude Code sandbox and Codex profile, macOS | verified by the `standard tier (macos-14)` CI job |
| Claude Code sandbox and Codex profile, Linux | verified by the `standard tier (ubuntu-latest)` CI job (bubblewrap and socat installed) |
| `openmoat run`, Windows | not run: `openmoat run` refuses on Windows, where OpenMoat generates no OS sandbox (#135) |
| Claude Code sandbox, Windows | not run: Claude Code's sandbox does not run on native Windows, so `openmoat init` writes no sandbox settings there ([SANDBOX.md](SANDBOX.md)) |
| Codex profile, Windows | not verified: the scripts and the project's `npm` shim are POSIX shell |

The Standard tier columns cover the commands the agent runs and the processes they start.
Not verified here: what the agent's own process does outside its sandbox (Claude Code's file
tools and hooks), a real model choosing the command, and the opt-in `sandbox.proxy_port` mode
for these scripts (the command-level scenarios of the differential suite use it, and the
`standard tier` jobs run them under both host sandboxes). `scripts/ci/host-binaries.sh` fetches the
pinned binaries, and `scripts/ci/differential.sh hostile_scripts` runs these rows under every layer
the machine has.

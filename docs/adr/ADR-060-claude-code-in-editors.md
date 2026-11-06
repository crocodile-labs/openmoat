# ADR-060: Claude Code in VS Code and JetBrains, and the editors' own files

Status: accepted · Date: 2026-11-06 · Builds on ADR-025 and ADR-053

## Context

Claude Code runs inside editors in two ways. The VS Code extension (and the same
extension in VS Code's forks) bundles its own Claude Code for its chat panel and puts no
`claude` on the search path; the extension's version is the bundled Claude Code's
version. The JetBrains plugin bundles nothing: it runs the `claude` on the search path or
the command its settings name (<https://code.claude.com/docs/en/vs-code>,
<https://code.claude.com/docs/en/jetbrains>). Both read `~/.claude/settings.json`, so
OpenMoat's `PreToolUse` hook already runs there. Five things were missing or wrong:

1. `openmoat init` writes `onFailure: "block"` only when it knows every Claude Code that
   reads the file reads that key (2.1.295 or later). It asked only the `claude` on the
   search path, so a person who uses only the VS Code extension got entries without the
   key, and a hook that failed let the call run.
2. On Windows without Git for Windows or Git Bash, Claude Code before 2.1.310 could let a
   call through that a hook refused (changelog 2.1.299, 2.1.309, 2.1.310). Nothing said
   so.
3. The editors' own MCP tools reach the hook as `mcp__ide__getDiagnostics`,
   `mcp__claude-vscode__getDiagnostics` and `mcp__ide__executeCode`. The generic MCP
   reading took the diagnostics tool's `uri` (a `file:` URI) for a host to contact, so the
   default `net: deny` refused the call, and it never read the file as a file, so a
   secret's diagnostics, which quote its lines, were not refused as `Read` of it is.
   `executeCode` runs Python in the notebook's kernel and was judged by its name alone.
4. The JetBrains docs warn that an agent allowed to edit files can edit IDE configuration
   that the IDE runs, and so get a command run that no prompt asked about. VS Code's
   project folder is the same: tasks, debug launches, MCP servers, and settings that name
   a program. Only `.vscode/tasks.json` needed review.
5. Cursor loads Claude Code's hooks by default and runs each with its own input, which it
   does not document (<https://cursor.com/docs/reference/third-party-hooks>). Read with
   Claude Code's field names, a Cursor `Grep` naming a secret in `file_path` is a search of
   the project, which is allowed; Cursor's `preToolUse` event name was an unknown event,
   a deny. Cursor also added `beforeTabFileRead`, the read of its inline completion,
   which no hook of OpenMoat's covered.

## Decision

1. **Bundled copies are a spec fact.** `HostSpec::bundled` lists the editors' extension
   folders and the extension id. The CLI reads each folder's `extensions.json` (or, when
   it is missing, the folder names) and never runs the bundled binary. `onFailure` is
   written when at least one copy is found and every copy found, on the search path or
   bundled, is 2.1.295 or later; an older copy beside a new one leaves it out, as an old
   `claude` on the search path did, since a key an older version rejects can stop every
   hook in the file. `openmoat status` and `openmoat doctor` name each bundled copy and
   warn about one too old.
2. **Windows hook fixes are advisories.** They join Claude Code's advisories, limited to
   Windows, so `status` and `doctor` warn for each copy older than 2.1.310. The 2.1.316
   PowerShell fix (a command starting with a type cast) and the 2.1.314 Monitor fix
   (hooks matching only `Bash`) do not touch OpenMoat's hook and are not listed.
3. **Editor tools are mapped.** `getDiagnostics` reads the file its `uri` names (a
   `file:` URI or an absolute path), else the working directory; it stays an MCP call by
   name with that read, so `mcp` rules and `secrets-paths` both apply. `executeCode` is
   `Unchecked`: at least `review`. Arguments other than these fall back to the generic
   MCP reading.
4. **The editors' project configuration is `runs-later`.** All of `.vscode/` and the
   folder itself, `*.code-workspace`, all of `.idea/` and the folder, and `*.run.xml`.
   A path rule cannot read keys, and too many VS Code settings name a program (terminal
   profiles, interpreters, linters' paths, the C/C++ compiler) for a list of files or
   keys to be complete. Agents rarely edit these; reading them stays allowed.
5. **A Cursor payload is read as Cursor's.** Claude Code's adapter reads a payload that
   carries `cursor_version` (a field of every Cursor hook input) with the Cursor
   adapter's `preToolUse` reading, through the registry, and decides it as a call that
   cannot prompt: a `review` is a deny, a `defer` is no answer. Cursor's `Shell` is the
   command it names. A Cursor `sessionStart` decides nothing.
6. **Tab reads are hooked.** `beforeTabFileRead` is installed with the other Cursor
   hooks. It answers only `permission`: `allow` for `allow` and `defer`, `deny` for
   anything else. Tab had no check before; it now refuses what the policy refuses an
   agent, and holding every file outside the project would only stop completions there.

## Alternatives

- **Write `onFailure` when any copy reads it.** Protects the up-to-date copy at the risk
  of an old one dropping every hook in the file; rejected.
- **Run the bundled binary for its version.** Slower and runs a program from an editor
  folder; the extension's version already says it.
- **Name only some `.vscode` files.** Leaves `c_cpp_properties.json`, `extensions.json`
  and every setting that names a program. Rejected for the whole folder.
- **Skip Cursor payloads in Claude Code's hook** (no answer). Leaves Cursor without even
  that check when the Cursor hooks are not set up; and the hook gives no wider answer
  than Cursor's own, which Cursor ranks above it.

## Consequences

- An agent's edit of `.vscode/settings.json` now needs review (the benign fixture became a
  review one); `.vscode-test.mjs`, `src/vscode/…` and files named like `.idea` do not.
- With both Cursor's hooks and Claude Code's set up, Cursor runs both for a call and the
  audit log has two rows for it, each with the same reading.
- Not covered: the editor selection and open-file context Claude Code adds to each
  prompt, which is no tool call; the JetBrains plugin's own command setting, which
  OpenMoat does not read (put the same `claude` on the search path); a VS Code
  `claudeCode.claudeProcessWrapper`, which runs another program as Claude Code.
- `executeCode`'s argument name (`code`) and `getDiagnostics`' (`uri`) are not in the
  docs; the input Cursor sends Claude Code's hook is not documented. Live tests confirm
  them (`host/claude_code/HOST.md`).

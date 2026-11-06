# Claude Code in VS Code and JetBrains

> **Read this when** you use Claude Code from the VS Code extension or the JetBrains
> plugin, or Cursor's editor, and want to know what OpenMoat checks there.

Since 0.17.0 the `claude-code` hook protects Claude Code in both editors exactly as in
the terminal: every tool call goes through `openmoat guard`, and a hook that fails to
start, crashes or times out blocks the call. There is no separate host to set up.

## Set up

```bash
openmoat init        # finds the VS Code extension's Claude Code too
openmoat status      # lists each Claude Code it found
```

`openmoat status` and `openmoat doctor` show a line such as `Claude Code 2.1.318 bundled
by the VS Code extension at ~/.vscode/extensions/anthropic.claude-code-2.1.318-darwin-arm64`
for each copy. Run `openmoat init` again after the extension updates from a version
before 2.1.295; `openmoat doctor` says when.

### VS Code (and its forks)

The extension bundles its own Claude Code for its chat panel and puts no `claude` on
your search path. OpenMoat reads the extension's version, which is the bundled Claude
Code's, from `extensions.json` in the extensions folder of VS Code, VS Code Insiders,
VS Code Server (remote hosts), Cursor, Windsurf and VSCodium. It runs nothing there.

`openmoat init` writes `onFailure: "block"`, the setting that makes a failed hook block
the call, only when every Claude Code it finds is 2.1.295 or later: an older copy may
reject the key and drop every hook in the file. If an old extension is left over, update
it or remove it, then run `openmoat init`.

### JetBrains

The plugin bundles no Claude Code: it runs the `claude` on your search path, or the
command you set in **Settings → Tools → Claude Code [Beta] → Claude command**. OpenMoat
does not read that setting, so if you set one, point it at the same `claude` that is on
your search path.

## What is checked

| In the editor | How OpenMoat decides it |
|---|---|
| Every Claude Code tool (`Bash`, `Read`, `Edit`, `WebFetch`, MCP tools, …) | as in the terminal |
| `getDiagnostics` (`mcp__ide__getDiagnostics`, and `mcp__claude-vscode__getDiagnostics` in the VS Code chat panel): the editor's errors and warnings, which quote the file's lines | a read of the file its `uri` names, else of the project: a secret's diagnostics are denied, a project file's are left to Claude Code as before |
| `executeCode` (`mcp__ide__executeCode`, VS Code): Python run in the open notebook's kernel | needs review; OpenMoat does not read Python. The editor still asks Execute or Cancel |
| A write to the editors' project configuration: `.vscode/` (tasks, launch configurations, MCP servers, settings that name a program), `*.code-workspace`, `.idea/`, JetBrains' shared `*.run.xml` | needs review (`runs-later`): the editor runs what these name, outside any prompt. Reading them stays allowed |
| A write to a virtual environment's interpreter and scripts (`.venv/bin/`, `venv/bin/`) | needs review (`runs-later`): the editor's Python extension and test runners start them outside any sandbox; an install still writes them |
| A write to dev container configuration (`.devcontainer/`, `.devcontainer.json`) | needs review (`runs-later`): its `initializeCommand` runs on this machine, not in the container, when the editor opens the folder |

Try it against your policy:

```bash
openmoat policy check "$PWD/.vscode/tasks.json" --kind fs-write   # exit 3: review (runs-later)
openmoat policy check "$PWD/src/main.rs" --kind fs-write          # exit 0: allow (project-fs)
openmoat policy check "$PWD/.vscode/tasks.json" --kind fs-read    # exit 0: allow
```

## Not covered

- **A repository's own git configuration.** `.git/config` can name programs git runs
  (`core.fsmonitor` on every `git status`, a hooks folder, a pager, filters, `!` aliases).
  The editor's git extension and the agent run git in the background when the folder
  opens, before any hook, so OpenMoat cannot stop it; `openmoat status` and `openmoat
  doctor` name each such key of the current repository (`repo_git_config` in
  `status --format json`). Under `openmoat run` the agent's git runs inside the sandbox;
  the editor's does not.
- **The editor selection and the open file.** Claude Code adds the text you select, and
  the path of the file you have open, to each prompt you send. That is no tool call, so no
  hook sees it. Claude Code's own `Read` deny rules keep a matching file's selection out;
  VS Code's `claudeCode.attachSelection` and `attachOpenFile` turn it off.
- **A process wrapper.** VS Code's `claudeCode.claudeProcessWrapper` runs another program
  as Claude Code; OpenMoat checks only what that program sends the hook.
- **A project that turns hooks off.** A repository's `.claude/settings.json` can set
  `disableAllHooks: true`, which turns OpenMoat's user hook off for that project in the
  editor as in the terminal. `openmoat status` and `openmoat doctor` report it. Only hooks
  in Claude Code's managed settings cannot be turned off from a project; put OpenMoat's
  entries there on a machine where that matters.
- **Windows before Claude Code 2.1.310.** Without Git for Windows or Git Bash, a hook's
  block could still let the call through; `status` and `doctor` warn about such a copy.

## Cursor's editor

Set up the `cursor` host (`openmoat init` does when `~/.cursor` exists). Since 0.17.0 it
also installs `beforeTabFileRead`: Tab, Cursor's inline completion, is refused a file the
policy refuses an agent (a secret, another agent's login) and reads every other file as
before.

Cursor also runs Claude Code's hooks from `~/.claude/settings.json` by default ("Include
Third-Party Plugins, Skills, and Other Configs"). OpenMoat reads such a call with Cursor's
field names and answers a review there as a deny. That hook is not Cursor's protection:
Cursor runs it fail-open and ranks its own hooks above it. With both set up, a call is in
the audit log twice.

Not covered in Cursor:

- **Cloud agents.** They do not load your user hooks (`~/.cursor/hooks.json`), so
  OpenMoat does not check them; a project's `.cursor/hooks.json` is the repository's,
  not yours.
- **Browser and other tools without a hook name.** Cursor's hook docs name no browser,
  web or memory tool for `preToolUse`. A tool that reaches `preToolUse` is decided
  (an unknown one as `tool.unknown`); one that does not is not checked.

Full details: [claude_code HOST.md](../crates/openmoat-hosts/src/host/claude_code/HOST.md),
[cursor HOST.md](../crates/openmoat-hosts/src/host/cursor/HOST.md),
[ADR-060](adr/ADR-060-claude-code-in-editors.md).

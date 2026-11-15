# OpenMoat in each agent's own plugin channel (preview)

Generated from the host specs (`crates/openmoat-hosts/src/host/<module>/plugin.rs`) by `OPENMOAT_TEST_UPDATE_PLUGINS=1 cargo test -p openmoat-hosts --test plugins`; do not edit. Design: [ADR-099](../docs/adr/ADR-099-plugin-packages.md); install steps: [docs/INSTALL.md](../docs/INSTALL.md#install-from-an-agents-plugin-channel-preview).

Each folder is a thin package for one agent's channel. It holds no binary and downloads nothing: it runs `openmoat guard --host <id> --plugin`, the command `openmoat init` writes plus the flag. the one the policy lock pins (`binary` in `~/.moat/policy.lock`, the absolute path `openmoat init` recorded); with no lock yet, one in `~/.cargo/bin` or Homebrew's folder, then the search path (the guard then denies every call until `openmoat init` writes the lock). When there is no `openmoat`, or it gives no answer, the call is blocked with: "OpenMoat is not installed: install it with `brew install crocodile-labs/tap/openmoat` (other ways: https://github.com/crocodile-labs/openmoat/blob/main/docs/INSTALL.md), then run `openmoat init`". Without a policy lock the guard denies every call and names `openmoat init`, which stays the source of the policy and its lock. Where `openmoat init`'s own hook for the agent is installed and pinned, the package gives no decision, so each call is decided once; `openmoat doctor` reports what the package did last.

**With a package alone**, without `openmoat init`'s hook: the package is outside the policy lock: the agent may update it, and you or a project's settings may turn it off, without OpenMoat seeing it. It decides only with the default state directory, `~/.moat` (a `MOAT_HOME` naming another is denied), and finds the lock there from the agent's `HOME`. Its guard script is POSIX `sh`, so native Windows needs `openmoat init`. `openmoat init`'s hook names its binary and state directory itself and is pinned by the lock, so keep it as the setup to rely on.

None of these is listed in its channel yet: each is a preview until it is.

| Agent | Folder | Channel | Install, once published | Format sources |
|---|---|---|---|---|
| Claude Code | [`claude-code/`](claude-code/) | Claude Code plugin marketplace | `claude plugin marketplace add crocodile-labs/openmoat-plugins && claude plugin install openmoat@crocodile-labs` | [1](https://code.claude.com/docs/en/plugins-reference) [2](https://code.claude.com/docs/en/plugin-marketplaces) [3](https://code.claude.com/docs/en/hooks) |
| Codex | none | none: Codex's Plugins Directory does not take plugins that carry hooks (https://learn.chatgpt.com/docs/plugins); `openmoat init` writes the hook, which you then trust in Codex's `/hooks` | `openmoat init` | |
| Cursor | [`cursor/`](cursor/) | Cursor Marketplace | `Cursor: Customize, find OpenMoat in the Marketplace, Install` | [1](https://cursor.com/docs/plugins) [2](https://cursor.com/docs/reference/plugins) [3](https://cursor.com/docs/agent/hooks) |
| OpenClaw | [`openclaw/`](openclaw/) | ClawHub | `openclaw plugins install clawhub:@openmoat/openclaw` | [1](https://docs.openclaw.ai/tools/clawhub) [2](https://docs.openclaw.ai/plugins/manifest) [3](https://docs.openclaw.ai/plugins/building-plugins) |
| GitHub Copilot CLI | [`copilot-cli/`](copilot-cli/) | GitHub Copilot CLI plugins | `copilot plugin install crocodile-labs/openmoat:plugins/copilot-cli` | [1](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference) [2](https://docs.github.com/en/copilot/reference/hooks-configuration) [3](https://github.com/github/copilot-cli/blob/main/changelog.md) |
| pi | [`pi/`](pi/) | pi packages (npm, pi.dev gallery) | `pi install npm:@openmoat/pi` | [1](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/packages.md) [2](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) |
| Gemini CLI | [`gemini-cli/`](gemini-cli/) | Gemini CLI extensions gallery | `gemini extensions install https://github.com/crocodile-labs/openmoat-gemini` | [1](https://geminicli.com/docs/extensions/reference/) [2](https://geminicli.com/docs/extensions/releasing/) [3](https://geminicli.com/docs/hooks/) |
| OpenCode | [`opencode/`](opencode/) | OpenCode plugins (npm) | `opencode plugin add @openmoat/opencode` | [1](https://opencode.ai/docs/plugins/) [2](https://opencode.ai/docs/build/plugins) |
| Hermes Agent | [`hermes/`](hermes/) | Hermes Agent Plugin Catalog | `hermes plugins install openmoat && hermes plugins enable openmoat` | [1](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins) [2](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/catalog-submission) [3](https://github.com/NousResearch/hermes-agent/blob/main/plugin-catalog/README.md) |
| Cline CLI | none | none: Cline's SDK plugins wait 3 s and ignore a failed hook unless they end the whole run (https://docs.cline.bot/sdk/plugins.md), weaker than the `PreToolUse` file `openmoat init` writes | `openmoat init` | |
| goose | none | none: goose has no registry for hook plugins, and `openmoat init` already writes OpenMoat as an Open Plugins folder | `openmoat init` | |
| Antigravity CLI | [`antigravity-cli/`](antigravity-cli/) | Antigravity CLI plugins | `agy plugin install https://github.com/crocodile-labs/openmoat-antigravity` | [1](https://antigravity.google/docs/plugins.md) [2](https://antigravity.google/docs/build-plugins.md) [3](https://antigravity.google/docs/hooks.md) |
| Qwen Code | none | none: Qwen Code's extensions (`qwen extensions install`) can carry hooks, but which manifest field holds them was not verified; `openmoat init` writes the hook into `settings.json` | `openmoat init` | |
| Crush | none | none: Crush has no plugin channel: Agent Skills are its only extensions, and a skill carries no hook | `openmoat init` | |

## Publishing

Nothing here is published by CI. For each package:

### Claude Code

1. Create the repository `crocodile-labs/openmoat-plugins` whose root is this `plugins/` folder (`git subtree split --prefix plugins` on a release commit), and push it; repeat on every release, since the plugin's `version` keeps people on the release it names.
2. Check it: `claude plugin validate ./plugins` and `claude plugin validate ./plugins/claude-code`, then `claude plugin marketplace add ./plugins` and `claude plugin install openmoat@crocodile-labs` with `CLAUDE_CONFIG_DIR` set to a throwaway directory.
3. Optionally submit it to Anthropic's directory (https://code.claude.com/docs/en/plugins/publish).

### Cursor

1. Publish the `plugins/` folder as the repository `crocodile-labs/openmoat-plugins` (the step the Claude Code plugin takes); its `.cursor-plugin/marketplace.json` lists `cursor/`.
2. Test it: copy `plugins/cursor` to `~/.cursor/plugins/local/openmoat` on a test account, then Developer: Reload Window.
3. Submit it at https://cursor.com/marketplace/publish; Cursor reviews it and every update before listing.

### OpenClaw

1. Test it with `openclaw plugins install ./plugins/openclaw` with `OPENCLAW_STATE_DIR` set to a throwaway directory, then restart the Gateway.
2. `clawhub package publish ./plugins/openclaw --dry-run`, then without `--dry-run`, signed in as Crocodile Labs; ClawHub scans each release before it is listed. Check first that ClawHub's plugin publishing works in the current OpenClaw release (2026.11.2-11.3 release notes report it incomplete).
3. Raise `compat` and `build` in `package.json` (from the OpenClaw release the weekly check last passed) when OpenMoat's plugin is checked against a newer one.

### GitHub Copilot CLI

1. Nothing to publish for the install command: it reads `plugins/copilot-cli` of this repository's default branch. Test it with `copilot plugin install ./plugins/copilot-cli` with `COPILOT_HOME` set to a throwaway directory (Copilot CLI 1.0.111 or later).
2. To be listed, open a pull request adding it to the `github/awesome-copilot` marketplace, or give `crocodile-labs/openmoat-plugins` a `.github/plugin/marketplace.json` (Copilot CLI also reads `.claude-plugin/marketplace.json`, which lists the Claude Code plugin, so the Copilot marketplace must be its own file in `.github/plugin/`).

### pi

1. Test it with `pi install ./plugins/pi` with `PI_CODING_AGENT_DIR` set to a throwaway directory.
2. From `plugins/pi`, `npm publish --access public` as a member of the `@openmoat` npm organisation (the one that publishes `@openmoat/sdk`), on every release.
3. The `pi-package` keyword lists it in the pi.dev gallery; nothing else to submit.

### Gemini CLI

1. Create the public repository `crocodile-labs/openmoat-gemini` whose root is `plugins/gemini-cli` (the manifest must be at the root), and push it on every release.
2. Test it: `gemini extensions link plugins/gemini-cli` with `GEMINI_CLI_HOME` set to a throwaway directory, in a trusted folder (untrusted folders run no hooks).
3. Add the GitHub topic `gemini-cli-extension` to the repository; the gallery crawls daily.

### OpenCode

1. Test it with OpenCode 1 and 2, each with `OPENCODE_CONFIG_DIR` set to a throwaway directory whose `opencode.json` lists the folder's path in `plugins` (OpenCode 2 loads a configured local directory).
2. From `plugins/opencode`, `npm publish --access public` as a member of the `@openmoat` npm organisation, on every release.
3. Open a pull request adding it to OpenCode's ecosystem page (https://opencode.ai/docs/ecosystem/).

### Hermes Agent

1. Test it: `hermes plugins validate plugins/hermes --install-deps`, then copy the folder into a throwaway Hermes home's plugins and enable it.
2. Copy `plugins/hermes/plugin-catalog-entry.yaml` to `plugin-catalog/openmoat.yaml` in a fork of `NousResearch/hermes-agent`, set `sha` to the full 40-character commit of `crocodile-labs/openmoat` that holds this release's `plugins/hermes`, and open a pull request; CI validates it and maintainers review it. Bump `sha` and `version` on every release.

### Antigravity CLI

1. Create the public repository `crocodile-labs/openmoat-antigravity` whose root is `plugins/antigravity-cli`, and push it on every release.
2. Test it with `agy plugin install ./plugins/antigravity-cli` in a throwaway home: Antigravity CLI is a preview host (no hook fired in the 2026-11-10 real run), so check that the plugin's hook fires before saying it protects anything.
3. For the curated marketplace, fill in Antigravity's interest form (https://antigravity.google/docs/marketplace.md).

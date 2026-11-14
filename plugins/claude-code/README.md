# OpenMoat for Claude Code (preview)

Checks each tool call Claude Code makes against OpenMoat's policy before it runs. Generated from OpenMoat's host specs; see [the plugins README](https://github.com/crocodile-labs/openmoat/blob/main/plugins/README.md) and [ADR-095](https://github.com/crocodile-labs/openmoat/blob/main/docs/adr/ADR-095-plugin-packages.md).

## Install

1. Install OpenMoat and set it up once: `brew install crocodile-labs/tap/openmoat`, then `openmoat init` in your own terminal (other ways: https://github.com/crocodile-labs/openmoat/blob/main/docs/INSTALL.md).
2. Install this package (Claude Code plugin marketplace): `claude plugin marketplace add crocodile-labs/openmoat-plugins && claude plugin install openmoat@crocodile-labs`

## What it does

It holds no binary and downloads nothing. For each call it runs the `openmoat` on the search path as `openmoat guard --host claude-code --plugin`. Without `openmoat`, or when it gives no answer, the call is blocked; without the policy lock `openmoat init` writes, every call is denied. Where `openmoat init`'s own hook for Claude Code is installed too, this package gives no decision, so each call is decided once. `openmoat doctor` shows when it last ran.

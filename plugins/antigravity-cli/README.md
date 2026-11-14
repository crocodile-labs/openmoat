# OpenMoat for Antigravity CLI (preview)

Checks each tool call Antigravity CLI makes against OpenMoat's policy before it runs. Generated from OpenMoat's host specs; see [the plugins README](https://github.com/crocodile-labs/openmoat/blob/main/plugins/README.md) and [ADR-099](https://github.com/crocodile-labs/openmoat/blob/main/docs/adr/ADR-099-plugin-packages.md).

## Install

1. Install OpenMoat and set it up once: `brew install crocodile-labs/tap/openmoat`, then `openmoat init` in your own terminal (other ways: https://github.com/crocodile-labs/openmoat/blob/main/docs/INSTALL.md).
2. Install this package (Antigravity CLI plugins): `agy plugin install https://github.com/crocodile-labs/openmoat-antigravity`

## What it does

It holds no binary and downloads nothing. For each call it runs `openmoat guard --host antigravity-cli --plugin`: the one the policy lock pins (`binary` in `~/.moat/policy.lock`, the absolute path `openmoat init` recorded); with no lock yet, one in `~/.cargo/bin` or Homebrew's folder, then the search path (the guard then denies every call until `openmoat init` writes the lock). Without `openmoat`, or when it gives no answer, the call is blocked; without the policy lock `openmoat init` writes, every call is denied. Where `openmoat init`'s own hook for Antigravity CLI is installed too, this package gives no decision, so each call is decided once. `openmoat doctor` shows when it last ran.

## With this package alone

the package is outside the policy lock: the agent may update it, and you or a project's settings may turn it off, without OpenMoat seeing it. It decides only with the default state directory, `~/.moat` (a `MOAT_HOME` naming another is denied), and finds the lock there from the agent's `HOME`. Its guard script is POSIX `sh`, so native Windows needs `openmoat init`. `openmoat init`'s hook names its binary and state directory itself and is pinned by the lock, so keep it as the setup to rely on.

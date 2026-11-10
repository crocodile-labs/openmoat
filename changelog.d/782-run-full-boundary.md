### Security
- `require.run: full-boundary` makes `openmoat run` refuse to start without an OS sandbox or, on Linux, without a network namespace for the agent, whatever `--netns` says; `openmoat status` and `openmoat doctor` report whether it holds on the system (ADR-077) ([#782](https://github.com/crocodile-labs/openmoat/pull/782)).

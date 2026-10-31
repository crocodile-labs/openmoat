### Security
- Codex hooks now invoke `guard --host codex` in one command string instead of ignored `args`, with safe quoting on POSIX and Windows. Existing hooks are repaired by `init`, `policy upgrade` and `sandbox sync`; status and doctor report broken or untrusted hooks, and bare OpenMoat denies hook input ([#705](https://github.com/crocodile-labs/openmoat/pull/705)).

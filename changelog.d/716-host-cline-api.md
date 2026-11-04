### Changed
- **Breaking** `openmoat-hosts`: `Host` gains `Cline`, `HookLayout` gains `Script` (a hook script OpenMoat owns whole), and `OwnedFile` gains a `syntax` field (`JavaScript` or `PosixShell`); an exhaustive `match` on these enums needs the new arms, and code that builds an `OwnedFile` sets `syntax` ([#716](https://github.com/crocodile-labs/openmoat/pull/716)).

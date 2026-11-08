### Security
- On Linux, the Codex profile also denies every letter case of its short workspace deny globs (`**/.env`, `**/.env.*`, `**/.envrc`, `**/.moat/**`), so a file spelled `.ENV` in a directory that folds case is hidden too; longer globs are reported as `codex.linux-case-variants` ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).

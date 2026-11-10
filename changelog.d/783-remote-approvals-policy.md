### Security
- The default policy's `kernel-self` rule denies agents reading `~/.moat/remote` (the approval channel's token and the key that signs requests, answers and the approver list) and running any `openmoat approvals` command, by either name, by path and under the pseudo-terminal wrappers (ADR-078) ([#783](https://github.com/crocodile-labs/openmoat/pull/783)).

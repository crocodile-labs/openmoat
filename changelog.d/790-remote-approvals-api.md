### Changed
- **Breaking** `openmoat-hosts`: `HookRequest` has a new field, `input`: the call's whole tool arguments as canonical JSON (keys sorted, no whitespace), `None` for an event without a tool call ([#790](https://github.com/crocodile-labs/openmoat/pull/790)).

### Changed
- `openmoat status`, `openmoat doctor` and the README say the Antigravity CLI is "not yet proven on a real agy": in OpenMoat's weekly check, agy 1.5.5 ran its tool calls in a headless run without starting OpenMoat's hook in `~/.gemini/config/hooks.json`. Treat its calls as unchecked until a run shows the hook deciding one ([#789](https://github.com/crocodile-labs/openmoat/pull/789)).

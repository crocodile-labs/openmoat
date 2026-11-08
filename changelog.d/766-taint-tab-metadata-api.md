### Changed
- **Breaking** `openmoat-core`: `TaintSettings` has a new public field `metadata_tools` (`Vec<String>`, the MCP tools whose results do not taint a session beyond the built-in list; set it to `Vec::new()` where you build the settings yourself, or start from `TaintSettings::default()`) ([#766](https://github.com/crocodile-labs/openmoat/pull/766)).

### Fixed
- The check for an agent among a command's parent processes recognises an agent started through an interpreter with options before its script (`node --no-warnings …/@github/copilot/index.js`, `bun --smol …`, `python3 -X utf8 …`), so person-only commands refuse it as they refuse `node …/index.js` ([#767](https://github.com/crocodile-labs/openmoat/pull/767)).

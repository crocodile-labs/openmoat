### Security
- Cursor's hook command writes the OpenMoat binary path in single quotes on macOS and Linux, so a `$`, backtick or `\` in the path is never run by Cursor's shell; `openmoat init` rewrites an existing entry, and `doctor` reads both forms ([#767](https://github.com/crocodile-labs/openmoat/pull/767)).

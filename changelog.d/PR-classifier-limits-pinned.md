### Security
- A download piped into a versioned Python (`curl … | python2.7`) is now denied by `pipe-to-shell` also when another command follows it on the line (`curl … | python2.7; true`); before, only the line ending in it was ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).

### Changed
- Tests pin the nesting limit (4 levels) and the brace limit (256 words): at the limit a command is classified as written, past it the call needs review; the shell fuzz target also checks that appending `; true` to a decided line never lowers its verdict ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).

### Changed
- Tests pin the nesting limit (4 levels) and the brace limit (256 words): at the limit a command is classified as written, past it the call needs review; the shell fuzz target also checks that appending `; true` to a decided line never lowers its verdict ([#768](https://github.com/crocodile-labs/openmoat/pull/768)).

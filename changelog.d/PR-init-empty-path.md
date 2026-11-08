### Fixed
- `openmoat init` from a shell whose `PATH` finds none of the programs it pins (an empty `PATH`) refuses with exit 64 and writes nothing, instead of recording a search path that pins nothing and reporting success; over an existing snapshot it keeps that one and says so ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).

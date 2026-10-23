### Fixed
- `openmoat bench` waits 45 s for a hook call, past `openmoat guard`'s own 30 s budget, instead of 10 s, so a guard that is only slow on a loaded machine is no longer killed and scored `error`; a step scored `error` now says why (exit code, start of stdout and stderr, time-out or start failure) ([#655](https://github.com/crocodile-labs/openmoat/pull/655)).

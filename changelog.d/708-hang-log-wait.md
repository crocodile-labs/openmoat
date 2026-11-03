### Fixed
- A guard that gives up after its 30 s budget now waits up to 2 s (was 200 ms) for its line in `~/.moat/guard-hangs.log` before it exits, so `openmoat doctor` no longer misses hangs when several guards give up at once on a slow disk; the deny still reaches every agent well before its hook timeout ([#708](https://github.com/crocodile-labs/openmoat/pull/708)).

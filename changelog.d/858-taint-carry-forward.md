### Fixed
- A long session no longer locks up after `openmoat policy upgrade`, a policy edit or an upgrade: the guard reads on from the session's earlier taint fold (never looser than it) while the new policy's own fold catches up, instead of folding every earlier call again and running out of time on each one (ADR-121) ([#858](https://github.com/crocodile-labs/openmoat/pull/858)).

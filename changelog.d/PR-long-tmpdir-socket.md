### Fixed
- `openmoat run` on Linux no longer refuses to start when `TMPDIR` is so long that its network namespace's socket could not be bound; the proof report's OS rows now run on Linux with bubblewrap (ADR-065).

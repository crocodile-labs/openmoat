### Changed
- The policy lock digests a settings file it pins by OpenMoat's part with the backend of the host whose file it is, found by the file's name, rather than with the first backend that pins by part; what the lock pins and its digests are unchanged ([#786](https://github.com/crocodile-labs/openmoat/pull/786)).

### Fixed
- goose: `openmoat status` and `doctor` report goose not protected in a directory whose `.agents/plugins/openmoat` replaces OpenMoat's plugin (any hook file but a byte-for-byte copy of OpenMoat's), name the directory to remove, and warn about the hooks of the project's other plugins; they used to report goose protected there ([#729](https://github.com/crocodile-labs/openmoat/pull/729)).

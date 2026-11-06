### Security
- Package-manager and build configuration that runs code on the next install, script or build (`.npmrc`, `.yarnrc`, `.yarnrc.yml`, `.cargo/config.toml`, `.cargo/config`, `bunfig.toml`) needs review in a clean session too (`runs-later`), and so do pip's and uv's user configuration and `~/.bunfig.toml` (`persistence`) ([#749](https://github.com/crocodile-labs/openmoat/pull/749)).

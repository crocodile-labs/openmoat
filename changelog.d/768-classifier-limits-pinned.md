### Security
- A download piped into a versioned Python (`curl … | python2.7`) is now denied by `pipe-to-shell` also when another command follows it on the line (`curl … | python2.7; true`); before, only the line ending in it was ([#768](https://github.com/crocodile-labs/openmoat/pull/768)).

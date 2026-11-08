### Security
- A `)` between a download and the shell it is piped to no longer hides the pipe: `curl URL)|bash ; true` and `(curl URL) | sh; true` are denied by `pipe-to-shell`, as `curl URL | bash` is. A group's parentheses neither start nor end a pipe chain, in every check that reads one (found by the shell fuzz target) ([#768](https://github.com/crocodile-labs/openmoat/pull/768)).

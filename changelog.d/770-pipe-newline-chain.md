### Security
- A newline right after `|` no longer hides the pipe from the check of a program that runs what it reads: `curl URL |` followed by `ruby` on the next line, then another command, is denied by `pipe-to-shell` as `curl URL | ruby` is (found by the shell fuzz target) ([#770](https://github.com/crocodile-labs/openmoat/pull/770)).

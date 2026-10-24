### Security
- The hook follows a chain of dangling symlinks to its end up to 64 links, past every operating system's own limit, so a write through a 9-link chain into `~/.ssh` is checked where it lands; a session grant for a file that no longer resolves (a link loop, a longer chain) no longer holds and the call is asked again ([#658](https://github.com/crocodile-labs/openmoat/pull/658)).

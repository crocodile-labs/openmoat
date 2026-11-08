### Security
- `openmoat run` on Linux refuses `pidfd_getfd`, which copies an open file (a socket, a token file) out of another process past every path rule; `pidfd_open` stays allowed ([#PR](https://github.com/crocodile-labs/openmoat/pull/PR)).

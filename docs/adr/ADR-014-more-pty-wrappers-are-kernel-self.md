# ADR-014: More pseudo-terminal wrappers around `moat allow` / `doctor --accept` are denied

Status: accepted · Date: 2026-10-05 · Refines ADR-011

## Context

ADR-011 denies `script`, `expect` and `unbuffer` running `moat allow|doctor|init|policy`, and
lists other ways to get a pseudo-terminal as not matched. An audit on 2026-10-05 found that
the gap was wider than those named exceptions: `/usr/bin/script -q /dev/null moat doctor
--accept` (the wrapper by absolute path) needed review while `script …` was denied, and
`python3 -c 'import pty; pty.spawn(["moat","doctor","--accept"])'`, `tmux new -d 'moat
allow …'` and `osascript -e 'tell app "Terminal" to do script "moat …"'` all needed review.

## Decision

- The `kernel-self` shell list also matches `script` and `expect` by absolute path
  (`*/script`, `*/expect`).
- It denies `python*` with an argument containing `pty`, `spawn(` and
  `moat allow|doctor|init|policy`; `tmux` and `screen` with `moat allow|doctor|init|policy`
  as separate arguments or inside one argument (`new`, `new-session`, `send-keys`, `-dm`);
  and `osascript` with an argument naming one of those commands. Each also by absolute path.
- Plain `python -c`, `tmux` and `osascript` usage is unaffected; the patterns require the
  kernel command to appear in the same command line.

## Consequences

- These spellings are denied before they run, consistent with the plain forms.
- It remains a pattern list. Splitting the command (`tmux send-keys moat Space allow`),
  building it at run time (`pty.spawn(["mo"+"at", …])`), `os.forkpty`, `socat … pty` or a
  compiled helper still only need review. ADR-011's conclusion stands: the complete answer is OS
  enforcement under `moat exec`, where the agent's process tree cannot write `~/.moat`.

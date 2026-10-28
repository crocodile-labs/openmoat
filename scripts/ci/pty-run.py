#!/usr/bin/env python3
"""Run one command with a pseudo-terminal as its standard input and output, as a
person at a terminal would, and exit with its exit code.

`openmoat uninstall` (and the other commands a person must run) refuse without a
terminal on standard input; a CI job has none. This gives the command a real
one, the same thing a terminal emulator gives it, and nothing else: it does not
set MOAT_ASSUME_TTY (honoured by debug builds only) or change the environment.
Nothing is typed into the terminal; the command's input ends at once.

    python3 -I scripts/ci/pty-run.py openmoat uninstall --purge

What the command writes to the terminal is copied to standard output.
"""

import os
import subprocess
import sys


def main(argv):
    if not argv:
        print("usage: pty-run.py <command> [<argument>...]", file=sys.stderr)
        return 64
    leader, follower = os.openpty()
    try:
        child = subprocess.Popen(
            argv, stdin=follower, stdout=follower, stderr=follower, start_new_session=True
        )
    except OSError as error:
        print(f"pty-run: {argv[0]}: {error}", file=sys.stderr)
        return 127
    finally:
        os.close(follower)
    out = sys.stdout.buffer
    while True:
        try:
            chunk = os.read(leader, 65536)
        except OSError:
            # Linux reports EIO on the leader once every copy of the follower is closed.
            break
        if not chunk:
            break
        out.write(chunk)
        out.flush()
    os.close(leader)
    code = child.wait()
    # A command killed by a signal exits as a shell reports it: 128 + the signal.
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

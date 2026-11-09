#!/bin/sh
# OpenMoat for Cline.
#
# Cline runs this file before every tool call, with the call as JSON on stdin,
# and reads only what it prints: `{"cancel": true, "errorMessage": ...}` stops
# the call, `{}` or nothing leaves it to Cline. Cline runs the call when a hook
# fails, so this script answers `cancel` itself whenever `openmoat guard` does
# not: it is missing, crashes, or exits without the reply it owes. `openmoat
# init` writes this file and the lock pins it; `openmoat uninstall` deletes it.
#
# The same file is Cline's `PostToolUse`, run after each call with what it
# returned (injected input, ADR-057). There it prints nothing, whatever
# `openmoat guard` answers: Cline would stop the whole run on a `cancel` after
# the call, which has already run. A failure goes to standard error only.
MOAT=__MOAT_BINARY__
# The state directory the guard decides with, from its command line and never
# from the environment Cline gives this script (ADR-071).
MOAT_STATE=__MOAT_HOME__
case ${0##*/} in
PostToolUse)
    "$MOAT" guard --host cline --home "$MOAT_STATE" >/dev/null || echo "openmoat: guard could not keep what this call returned; run openmoat doctor in a terminal" >&2
    exit 0
    ;;
esac
reply=$("$MOAT" guard --host cline --home "$MOAT_STATE")
status=$?
case $status in
0)
    # allow (`{}`) or defer (nothing)
    printf '%s\n' "$reply"
    exit 0
    ;;
2)
    # deny: the reply holds the `cancel`
    if [ -n "$reply" ]; then
        printf '%s\n' "$reply"
        exit 0
    fi
    ;;
esac
printf '{"cancel": true, "errorMessage": "moat: deny [hook-failure] openmoat guard exited %s without an answer, so the call is blocked; run openmoat doctor in a terminal"}\n' "$status"
exit 0

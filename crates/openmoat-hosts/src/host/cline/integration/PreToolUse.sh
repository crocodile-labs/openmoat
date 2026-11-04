#!/bin/sh
# OpenMoat for Cline.
#
# Cline runs this file before every tool call, with the call as JSON on stdin,
# and reads only what it prints: `{"cancel": true, "errorMessage": ...}` stops
# the call, `{}` or nothing leaves it to Cline. Cline runs the call when a hook
# fails, so this script answers `cancel` itself whenever `openmoat guard` does
# not: it is missing, crashes, or exits without the reply it owes. `openmoat
# init` writes this file and the lock pins it; `openmoat uninstall` deletes it.
MOAT=__MOAT_BINARY__
reply=$("$MOAT" guard --host cline)
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

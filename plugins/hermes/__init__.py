"""OpenMoat for Hermes Agent: checks every tool call with `openmoat guard`.

Generated from OpenMoat's host specs (plugins/README.md); do not edit.

Hermes calls `register(ctx)` once at start; the plugin registers a
`pre_tool_call` callback. For each call it sends `openmoat guard --host hermes
--plugin` the JSON Hermes's own `pre_tool_call` shell hook gets, the hook
`openmoat init` writes, and turns the answer into the callback's directive:
`{"decision": "block"}` blocks the call, `{"action": "approve"}` goes to
Hermes's approval prompt, no answer or `{}` lets it run. The guard gives no
decision where `openmoat init`'s own hook is installed and pinned, so each
call is decided once (ADR-099).

Hermes logs and skips a callback that raises, which would run the call
unchecked, so every failure here returns a block instead: no `openmoat`, a
crash, an exit code other than 0 or 2, an answer that cannot be read, or no
answer within GUARD_TIMEOUT_S. Hermes itself blocks a callback that outlasts
`plugins.hook_callback_timeout` (30 s by default). No dependencies; this file
downloads and installs nothing.
"""

import json
import os
import shutil
import subprocess

HOST = "hermes"
EVENT = "pre_tool_call"
FLAG = "--plugin"
PROGRAM = "openmoat"
NOT_INSTALLED = "OpenMoat is not installed: install it with `brew install crocodile-labs/tap/openmoat` (other ways: https://github.com/crocodile-labs/openmoat/blob/main/docs/INSTALL.md), then run `openmoat init`"
INSTALL_DIRS = ["$HOME/.cargo/bin","/opt/homebrew/bin","/usr/local/bin","/home/linuxbrew/.linuxbrew/bin"]
LOCK_FILE = ".moat/policy.lock"
LOCK_UNUSABLE = "the policy lock (`~/.moat/policy.lock`) names no `openmoat` this package can run: reinstall OpenMoat, then run `openmoat init`"
# Above `openmoat guard`'s own 30 s budget.
GUARD_TIMEOUT_S = 45


def _block(why):
    return {"action": "block", "message": f"OpenMoat blocked this call: {why}"}


def _runnable(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _program():
    """The program to run, or None when there is none.

    The one the policy lock pins (`binary` in ~/.moat/policy.lock, the absolute
    path `openmoat init` recorded); with no lock yet, one in a folder
    OpenMoat's installers use, then the search path, which the agent's
    environment decides and so comes last, where the guard denies every call
    until `openmoat init` writes the lock (ADR-099). Raises LockUnusable when
    the lock names no program this can run.
    """
    lock = os.path.join(os.path.expanduser("~"), LOCK_FILE)
    try:
        with open(lock, encoding="utf-8") as file:
            text = file.read()
    except FileNotFoundError:
        text = None
    except OSError as error:
        raise LockUnusable() from error
    if text is not None:
        try:
            binary = json.loads(text).get("binary")
        except (ValueError, AttributeError) as error:
            raise LockUnusable() from error
        if not isinstance(binary, str) or not os.path.isabs(binary) or not _runnable(binary):
            raise LockUnusable()
        return binary
    for folder in INSTALL_DIRS:
        path = os.path.join(os.path.expandvars(folder), PROGRAM)
        if _runnable(path):
            return path
    return shutil.which(PROGRAM)


class LockUnusable(Exception):
    """The policy lock names no program this plugin can run."""


def _payload(tool_name, args, kwargs):
    """What Hermes's `pre_tool_call` shell hook gets on stdin."""
    extra = {
        key: kwargs.get(key)
        for key in ("task_id", "tool_call_id", "turn_id", "api_request_id")
        if kwargs.get(key) is not None
    }
    return {
        "hook_event_name": EVENT,
        "tool_name": tool_name,
        "tool_input": args if isinstance(args, dict) else None,
        "session_id": kwargs.get("session_id") or "",
        "cwd": os.getcwd(),
        "extra": extra,
    }


def _answer(code, stdout, stderr):
    """The directive for the guard's exit code and output."""
    text = stdout.strip()
    if code not in (0, 2):
        first = (stderr.strip().splitlines() or ["no answer"])[0]
        return _block(f"openmoat guard exited {code}: {first}")
    if text == "":
        return None if code == 0 else _block("openmoat guard denied without an answer")
    try:
        reply = json.loads(text)
    except ValueError:
        return _block("openmoat guard gave no readable answer")
    if not isinstance(reply, dict):
        return _block("openmoat guard gave no readable answer")
    if reply.get("decision") == "block":
        return {"action": "block", "message": str(reply.get("reason") or "OpenMoat: deny")}
    if code == 0 and reply.get("action") == "approve":
        return reply
    if code == 0 and reply == {}:
        return None
    return _block(f"openmoat guard exited {code} with an answer it should not give: {text}")


def check(tool_name=None, args=None, task_id=None, **kwargs):
    """Hermes's `pre_tool_call` callback: a directive, or None to let the call run."""
    try:
        program = _program()
        if program is None:
            return _block(NOT_INSTALLED)
        if task_id is not None:
            kwargs["task_id"] = task_id
        run = subprocess.run(
            [program, "guard", "--host", HOST, FLAG],
            input=json.dumps(_payload(tool_name, args, kwargs)),
            capture_output=True,
            text=True,
            timeout=GUARD_TIMEOUT_S,
            check=False,
        )
        return _answer(run.returncode, run.stdout, run.stderr)
    except LockUnusable:
        return _block(LOCK_UNUSABLE)
    except subprocess.TimeoutExpired:
        return _block("openmoat guard did not answer in time")
    except Exception as error:  # noqa: BLE001 - every failure must block
        return _block(f"the OpenMoat plugin failed: {error}")


def register(ctx):
    ctx.register_hook(EVENT, check)

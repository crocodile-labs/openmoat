"""Deciding actions with the real `openmoat policy check`, in a throwaway home.

Every action is one `openmoat policy check --policy <file> --kind <kind> --format json`
run of the binary under test, with `HOME` pointed at an empty directory under the
system temporary directory and a scratch project as `--project` and `--cwd`, so the
person's own `~/.moat`, agent settings and project never take part. Identical actions
are decided once. Nothing an action names is executed: the binary only decides.
"""

import json
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# The order "strictest wins" reads verdicts in (AGENTS.md invariant 2).
STRICTNESS = {"deny": 4, "review": 3, "defer": 2, "allow": 1}
KINDS = ("shell", "fs-read", "fs-write", "net", "fetch", "mcp")
# Variables that point an agent or OpenMoat at a real configuration directory.
SCRUBBED = (
    "MOAT_HOME",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "GEMINI_CLI_HOME",
    "COPILOT_HOME",
    "PI_CODING_AGENT_DIR",
)


class Scratch:
    """A throwaway home and project; removed when the run ends.

    `home` replaces the throwaway home with the home the dataset's cases assume
    (`/root` for RedCode's container, `/home/user` for agent-egress-bench), so
    `~` means what the case means. It is only named, never created or written:
    `policy check --policy` reads nothing under it. `parent` is where the
    throwaway folder goes: Claude Code's own temporary folder (`/tmp/claude-*`)
    is one the default policy lets agents read, so a run started there would
    see allows a real home and project never get.
    """

    def __init__(self, home=None, parent=None):
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        self._dir = tempfile.TemporaryDirectory(prefix="openmoat-external-bench-", dir=parent)
        root = Path(self._dir.name)
        self.project = root / "project"
        self.project.mkdir()
        if home:
            self.home = Path(home)
        else:
            self.home = root / "home"
            self.home.mkdir()

    def close(self):
        self._dir.cleanup()

    def env(self):
        env = {k: v for k, v in os.environ.items() if k not in SCRUBBED}
        env["HOME"] = str(self.home)
        return env


class Decider:
    """Decides (kind, value) actions with the binary, caching identical ones."""

    def __init__(self, binary, policy, scratch, jobs):
        self.binary = str(binary)
        self.policy = str(policy)
        self.scratch = scratch
        self.jobs = jobs
        self.cache = {}

    def _one(self, action):
        kind, value = action
        if kind not in KINDS:
            raise ValueError(f"unknown action kind {kind!r}")
        project = str(self.scratch.project)
        argv = [
            self.binary, "policy", "check", "--policy", self.policy, "--kind", kind,
            "--project", project, "--cwd", project, "--format", "json", "--", value,
        ]
        done = subprocess.run(
            argv, cwd=project, env=self.scratch.env(), capture_output=True,
            text=True, timeout=60, check=False,
        )
        try:
            decision = json.loads(done.stdout)
        except json.JSONDecodeError:
            return {
                "verdict": "error",
                "rules": [],
                "reason": f"exit {done.returncode}: {done.stderr.strip()[:300]}",
            }
        return {
            "verdict": decision.get("verdict", "error"),
            "rules": rules_of(decision),
            "reason": "; ".join(map(str, decision.get("reasons") or []))[:300],
        }

    def decide_all(self, actions):
        """Decide every action not yet in the cache, `jobs` at a time."""
        todo = sorted({a for a in actions if a not in self.cache})
        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            for action, result in zip(todo, pool.map(self._one, todo)):
                self.cache[action] = result

    def get(self, action):
        return self.cache[action]


def rules_of(decision):
    """The rule ids a decision names, however the JSON spells them."""
    rules = decision.get("rules")
    if isinstance(rules, list):
        return [r if isinstance(r, str) else str(r.get("id", r)) for r in rules]
    rule = decision.get("rule")
    return [str(rule)] if rule else []


def strictest(results):
    """The strictest verdict of several actions, or `error` if any was not decided."""
    verdicts = [r["verdict"] for r in results]
    known = [v for v in verdicts if v in STRICTNESS]
    if len(known) < len(verdicts):
        return "error"
    return max(known, key=STRICTNESS.get) if known else "error"

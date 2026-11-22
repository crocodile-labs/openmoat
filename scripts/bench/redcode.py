"""RedCode-Exec cases as the tool calls a coding agent sends OpenMoat.

RedCode-Exec (AI-secure/RedCode, `dataset/RedCode-Exec/`) holds risky Python and
Bash snippets, 30 per risk scenario, each given to an agent as code, as a summary
and as detailed steps. The three prompts share one snippet, so the snippet is the
case here: what reaches OpenMoat is the call that runs it, not the prompt.

Each snippet becomes two forms, scored apart:

- `inline`: the code itself in the shell command. Bash: the script text as the
  command line. Python: `python3 -c '<code>'`, the code quoted as one argument.
  The guard sees every word of the code.
- `file`: the agent writes the script into the project, then runs it
  (`python3 redcode_task.py`, `bash redcode_task.sh`). The guard sees a write of a
  project file and a command that runs it; the code is in neither.

Both are ways agents run code today; the `file` form shows what the decision engine
cannot see on its own (the sandbox, docs/SANDBOX.md, is what limits that run).
The dataset is read as JSON only; no snippet is ever executed.
"""

import json
import re
import shlex
from pathlib import Path

LANGUAGES = {"py2text_dataset_json": "python", "bash2text_dataset_json": "bash"}
# Scenarios whose snippet only computes and prints: biased scoring (12), a loose
# IP regex (15), a timing leak in a comparison (16), privilege calls that only
# print (17), a seeded random generator (19), unsalted hashing (20), a missing
# default case (22), a flawed workflow (23), a duplicate key (25), a memory leak
# (27). The risk is in the code's logic, not in a call to the machine, so no
# tool-call guard can see it; they are scored apart ("logic only") and still
# counted in the totals. Judged from the snippets, not taken from RedCode.
LOGIC_ONLY = {12, 15, 16, 17, 19, 20, 22, 23, 25, 27}
INDEX = re.compile(r"^index(\d+)_")


def cases(dataset, project):
    """Yield one case per snippet: its id, scenario, and actions per form."""
    root = Path(dataset) / "dataset" / "RedCode-Exec"
    if not root.is_dir():
        raise SystemExit(f"{root} is not a RedCode-Exec dataset folder")
    for folder, language in LANGUAGES.items():
        for path in sorted((root / folder).glob("*.json"), key=_scenario_of):
            scenario = _scenario_of(path)
            for item in json.loads(path.read_text(encoding="utf-8")):
                code = item.get("Code", "")
                yield {
                    "id": f"{language}-{item['Index']}",
                    "category": f"{language} {scenario:02d}",
                    "summary": item.get("Text_summary", ""),
                    "attack": True,
                    "scope": "logic only" if scenario in LOGIC_ONLY else "acts on the machine",
                    "forms": _forms(language, code, project),
                }


def _scenario_of(path):
    match = INDEX.match(path.name)
    return int(match.group(1)) if match else 0


def _forms(language, code, project):
    if language == "bash":
        script = f"{project}/redcode_task.sh"
        return {
            "inline": [("shell", code)],
            "file": [("fs-write", script), ("shell", "bash redcode_task.sh")],
        }
    script = f"{project}/redcode_task.py"
    return {
        "inline": [("shell", "python3 -c " + shlex.quote(code))],
        "file": [("fs-write", script), ("shell", "python3 redcode_task.py")],
    }

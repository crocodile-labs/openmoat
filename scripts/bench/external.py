#!/usr/bin/env python3
"""Measure OpenMoat's decision engine against outside benchmark datasets.

Turns each case of RedCode-Exec or agent-egress-bench into the tool calls a
coding agent would ask OpenMoat about, decides every call with the real
`openmoat policy check` against a policy file, and scores the verdicts
(docs/BENCHMARKS.md has the method and the results). The datasets are not part of
this repository: download one and pass its folder. Its cases are read as JSON and
never executed, and nothing from it is imported or run.

    cargo build -p openmoat --bin openmoat
    python3 -I scripts/bench/external.py redcode ../RedCode \\
        --openmoat target/debug/openmoat \\
        --policy crates/openmoat-core/policies/default-v1.yaml \\
        --json redcode.json --markdown redcode.md
    python3 -I scripts/bench/external.py egress ../agent-egress-bench ...

Standard library only. `HOME` is a throwaway directory for every call.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# `-I` leaves the script's own folder off the import path; add it back, and only it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import decide  # noqa: E402
import egress  # noqa: E402
import redcode  # noqa: E402
import report  # noqa: E402


def main():
    args = _parse()
    scratch = decide.Scratch(args.home, args.scratch)
    try:
        decider = decide.Decider(args.openmoat, args.policy, scratch, args.jobs)
        if args.benchmark == "redcode":
            cases = list(redcode.cases(args.dataset, scratch.project))
        else:
            cases = list(egress.cases(args.dataset))
        decider.decide_all(a for c in cases for f in c["forms"].values() for a in f)
        for case in cases:
            case["forms"] = {
                name: _decided(actions, decider, scratch.project)
                for name, actions in case["forms"].items()
            }
    finally:
        scratch.close()
    summary = report.summarise(args.benchmark, cases)
    if args.json:
        Path(args.json).write_text(
            json.dumps({"summary": summary, "cases": cases}, indent=1) + "\n",
            encoding="utf-8",
        )
    text = report.markdown(args.benchmark, summary, cases)
    if args.markdown:
        Path(args.markdown).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    # A call the binary could not decide is a failed run, not a verdict.
    return 1 if any(form["error"] for form in summary["forms"].values()) else 0


def _decided(actions, decider, project):
    results = []
    for kind, value in actions:
        result = dict(decider.get((kind, value)))
        # The throwaway project's path changes every run and names the machine's
        # folders; keep results comparable and free of local paths.
        result["action"] = [kind, value.replace(str(project), "${project}")]
        result["reason"] = result["reason"].replace(str(project), "${project}")
        results.append(result)
    return {"verdict": decide.strictest(results), "actions": results}


def _parse():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("benchmark", choices=("redcode", "egress"))
    parser.add_argument("dataset", help="the downloaded dataset's top folder")
    parser.add_argument("--openmoat", required=True, help="the openmoat binary")
    parser.add_argument("--policy", required=True, help="the policy file to decide with")
    parser.add_argument(
        "--home",
        help="the home the cases assume (`/root`, `/home/user`); named, never written. "
        "Defaults to an empty throwaway folder",
    )
    parser.add_argument(
        "--scratch",
        help="where the throwaway project goes; defaults to the system temporary folder",
    )
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    parser.add_argument("--json", help="write every case and verdict here")
    parser.add_argument("--markdown", help="write the tables here instead of stdout")
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(main())

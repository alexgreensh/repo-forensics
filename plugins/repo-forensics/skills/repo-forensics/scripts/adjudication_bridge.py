#!/usr/bin/env python3
"""Run optional advisory lanes outside the deterministic scan process."""

import json
import os
import shlex
import subprocess
import sys

import adjudication


def command_runner(role, prompt):
    variable = "REPO_FORENSICS_CONFIRM_COMMAND" if role == "confirm" else "REPO_FORENSICS_REFUTE_COMMAND"
    command = os.environ.get(variable, "")
    if not command:
        raise RuntimeError("advisory lane unavailable")
    result = subprocess.run(
        shlex.split(command), input=prompt, capture_output=True, text=True,
        timeout=30, check=False, env={"PATH": os.environ.get("PATH", "")},
    )
    if result.returncode != 0:
        raise RuntimeError("advisory lane failed")
    return json.loads(result.stdout)


def main():
    report = json.load(sys.stdin)
    result = adjudication.build_advisory_annotations(
        report.get("findings", []), command_runner
    )
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# The code-scanning gate must FAIL CLOSED.
#
# History. `codeql-gate` in .github/workflows/_security.yml (since moved, as
# the `alerts` job, to .github/workflows/codeql.yml) counted open alerts with:
#
#   ALERTS=$(gh api '.../code-scanning/alerts?state=open' --jq 'length' 2>/dev/null || echo "0")
#
# That reads as defensive and is the exact opposite. The job declared no
# `permissions:` block, so it inherited the workflow's `contents: read` and the
# alert API answered 403. `gh` writes the API error BODY to stdout, so `ALERTS`
# became the string
#
#   {"message":"Resource not accessible by integration",...,"status":"403"}0
#
# every `[ ... -gt ... ]` then failed as a non-integer comparison, the `if` took
# its false branch, and the step printed "CodeQL gate passed (0 alerts)" and
# exited 0. Observed live in a GREEN run (34700514102 / job 103571322660), while
# the repository had an open high-severity alert.
#
# A security gate that cannot read its input must stop the build, not wave it
# through. This test pins both halves of that: the permission that makes the
# read possible, and the fail-closed handling for when it still is not. It also
# pins where the gate runs: never in PR CI (it starved PR CI of runners), on
# push to main, and inside the dry run and the release, whose verify needs it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

python3 - "$ROOT" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
failures: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


workflow_dir = root / ".github" / "workflows"
workflow = (workflow_dir / "codeql.yml").read_text(encoding="utf-8")


def job_body(source: str, job: str) -> str | None:
    m = re.search(rf"\n  {re.escape(job)}:\n(?P<body>(?:    .*\n|\n)*)", source)
    return m.group("body") if m else None


# Isolate the alerts job so a permission granted to some OTHER job cannot
# satisfy this test. (It was _security.yml's codeql-gate job until CodeQL
# left PR CI; the logic moved unchanged.)
gate = job_body(workflow, "alerts")
require(gate is not None, "codeql.yml no longer defines an alerts job")
body = gate or ""
require(
    re.search(r"^    needs: \[analyze\]\s*$", body, re.M) is not None,
    "codeql.yml alerts must need analyze -- it counts the alerts that analysis uploaded",
)

# 1. The read has to be possible at all.
require(
    re.search(r"^    permissions:\s*$", body, re.M) is not None,
    "alerts must declare its own permissions block -- inheriting the "
    "workflow default leaves it without security-events access and the alert "
    "API answers 403",
)
require(
    re.search(r"^      security-events:\s*read\s*$", body, re.M) is not None,
    "alerts must request security-events: read, or the code-scanning "
    "alert query 403s and the gate cannot see any alert",
)

# 2. The failure direction. `|| echo "0"` on the alert query is the specific
#    construct that turned an API error into a clean pass.
require(
    re.search(r"code-scanning/alerts[^\n]*\|\|\s*echo", body) is None,
    "the alert count must not fall back to a literal on error -- an unreadable "
    "alert list is not zero alerts",
)
require(
    "BLOCKED: cannot read code scanning alerts" in body,
    "alerts must fail with a named error when the alert API cannot be read",
)
require(
    re.search(r"alert count was not a number", body) is not None,
    "alerts must reject a non-numeric alert count instead of comparing it",
)

# 3. The count is produced in a command substitution, so a bare `exit` inside
#    the helper would end only the subshell and let the caller proceed with an
#    empty value -- the same class of silent pass. The callers must check.
assignments = re.findall(r"^\s*ALERTS2?=\$\(count_open_alerts\)(.*)$", body, re.M)
require(
    len(assignments) >= 2,
    "expected both alert samples to go through the checked helper",
)
require(
    all("|| exit 1" in tail for tail in assignments),
    "every count_open_alerts call must be followed by || exit 1 -- a failure "
    "inside a command substitution does not stop the caller on its own",
)

# 4. Where CodeQL runs. Never per pull request (a per-PR analysis plus a PR-CI
#    job waiting up to 150 min for it starved PR CI of runners); on push to
#    main, and callable so the dry run and the release can require it.
on = re.search(r"(?ms)^on:\n(?P<body>.*?)(?=^\S)", workflow)
triggers = set(re.findall(r"(?m)^  ([a-z_]+):", on.group("body"))) if on else set()
require("pull_request" not in triggers and "pull_request_target" not in triggers,
        "codeql.yml must not run per pull request")
require({"push", "workflow_call"} <= triggers,
        f"codeql.yml must run on push to main and be callable, has {sorted(triggers)}")
require(re.search(r"(?m)^  push:\n    branches: \[main\]$", workflow) is not None,
        "codeql.yml's push trigger must be main")
for name in ("pr.yml", "_security.yml"):
    code = "\n".join(
        line for line in (workflow_dir / name).read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    require("codeql" not in code.lower(),
            f"{name} must neither run nor wait for CodeQL (PR CI)")

# 5. Every caller must GRANT what codeql.yml's jobs request. A reusable
#    workflow cannot request more permission than its caller holds: asking for
#    security-events from a caller that grants only contents:read does not
#    downgrade, it fails the entire run with a startup_failure before a single
#    job executes. The caller list is DERIVED, never hardcoded: an earlier
#    revision listed callers by hand and stayed green while a third caller
#    nobody had listed failed every run at startup.
callers = sorted(
    path.name
    for path in workflow_dir.glob("*.yml")
    if "uses: ./.github/workflows/codeql.yml" in path.read_text(encoding="utf-8")
)
require(
    {"dry-run.yml", "release.yml"} <= set(callers),
    "the dry run and the release must call codeql.yml (their CodeQL pass), callers: "
    + (", ".join(callers) or "none"),
)
for caller_name in callers:
    caller = (workflow_dir / caller_name).read_text(encoding="utf-8")
    call_body = job_body(caller, "codeql") or ""
    require(
        "uses: ./.github/workflows/codeql.yml" in call_body,
        f"{caller_name} must call codeql.yml from a job named codeql",
    )
    for perm, level in (("security-events", "write"), ("actions", "read"), ("contents", "read")):
        require(
            re.search(rf"^      {perm}:\s*{level}\s*$", call_body, re.M) is not None,
            f"{caller_name} must grant {perm}: {level} to the codeql job -- a "
            "called workflow cannot request more than its caller grants, and the "
            "run fails at startup rather than degrading",
        )

# 6. The release publishes nothing without the CodeQL pass.
release = (workflow_dir / "release.yml").read_text(encoding="utf-8")
verify = job_body(release, "verify") or ""
require(re.search(r"(?m)^    needs: \[[^\]]*\bcodeql\b[^\]]*\]$", verify) is not None,
        "release.yml verify must need the codeql job")
require("needs.codeql.result == 'success'" in verify,
        "release.yml verify must require needs.codeql.result == 'success'")

if failures:
    print("Security gate fail-closed contract FAILED:")
    for failure in failures:
        print(f"  - {failure}")
    sys.exit(1)

print("Security gate fail-closed contract passed")
PY

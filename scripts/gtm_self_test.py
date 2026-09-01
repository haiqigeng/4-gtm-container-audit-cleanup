#!/usr/bin/env python3
"""Run the maintained GTM skill regression and repository checks."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def run(
    root: Path,
    name: str,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env=env,
    )
    return {
        "name": name,
        "status": "pass" if result.returncode == 0 else "fail",
        "return_code": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument(
        "--allow-untracked",
        action="store_true",
        help="Allow newly created referenced files during local development.",
    )
    parser.add_argument(
        "--code-only",
        action="store_true",
        help="Run repository checks without claiming workbook-runtime validation.",
    )
    parser.add_argument("--artifact-node", type=Path)
    parser.add_argument("--artifact-node-modules", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    python = sys.executable
    artifact_node = args.artifact_node or (
        Path(os.environ["CODEX_NODE"]) if os.environ.get("CODEX_NODE") else None
    )
    artifact_modules = args.artifact_node_modules or (
        Path(os.environ["CODEX_ARTIFACT_NODE_MODULES"])
        if os.environ.get("CODEX_ARTIFACT_NODE_MODULES")
        else None
    )
    runtime_errors = []
    if not args.code_only:
        if not artifact_node or not artifact_node.is_file():
            runtime_errors.append("bundled artifact Node.js path is missing")
        if not artifact_modules or not (
            artifact_modules / "@oai" / "artifact-tool" / "package.json"
        ).is_file():
            runtime_errors.append("bundled artifact-tool node_modules path is missing")
    child_env = dict(os.environ)
    if artifact_node:
        child_env["CODEX_NODE"] = str(artifact_node.resolve())
    if artifact_modules:
        child_env["CODEX_ARTIFACT_NODE_MODULES"] = str(artifact_modules.resolve())
    release_command = [python, "-B", "scripts/check_release.py"]
    if args.allow_untracked:
        release_command.append("--allow-untracked")
    checks = []
    if runtime_errors:
        checks.append(
            {
                "name": "artifact_runtime",
                "status": "fail",
                "return_code": 2,
                "stdout": "",
                "stderr": "; ".join(runtime_errors),
            }
        )
    elif not args.code_only:
        checks.append(
            run(
                root,
                "artifact_runtime",
                [
                    str(artifact_node),
                    "scripts/gtm_workbook_build.mjs",
                    "--preflight",
                ],
                env=child_env,
            )
        )
    checks.extend([
        run(
            root,
            "unittest",
            [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
            env=child_env,
        ),
        run(root, "release_layout", release_command),
        run(
            root,
            "vendor_registry",
            [python, "-B", "scripts/gtm_vendor_registry.py", "--max-age-days", "365"],
        ),
    ])
    if importlib.util.find_spec("ruff") is not None:
        checks.append(
            run(root, "ruff", [python, "-m", "ruff", "check", "--no-cache", "scripts", "tests"])
        )
    report = {
        "kind": "gtm_skill_self_test",
        "mode": "code_only" if args.code_only else "release_complete",
        "status": "pass" if all(item["status"] == "pass" for item in checks) else "fail",
        "checks": checks,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

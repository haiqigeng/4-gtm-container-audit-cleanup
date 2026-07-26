#!/usr/bin/env python3
"""Build and verify a deterministic identity for the runnable skill tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tomllib
from pathlib import Path
from typing import Any

MANIFEST_NAME = ".skill-build-manifest.json"
ROOT_FILES = ("SKILL.md", "LICENSE", "pyproject.toml")
ROOT_DIRECTORIES = ("agents", "references", "scripts")
EXCLUDED_NAMES = {
    MANIFEST_NAME,
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".mypy_cache",
    "gtm_self_test.py",
    "check_release.py",
    "build_skill_package.py",
    "release_blocklist.txt",
}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".tmp", ".bak")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_files(root: Path) -> list[Path]:
    """Return exactly the files copied into a clean runtime bundle."""
    paths = [
        root / filename
        for filename in ROOT_FILES
        if (root / filename).is_file()
    ]
    for dirname in ROOT_DIRECTORIES:
        directory = root / dirname
        if not directory.is_dir():
            continue
        paths.extend(
            path
            for path in directory.rglob("*")
            if path.is_file()
            and not any(part in EXCLUDED_NAMES for part in path.parts)
            and path.name not in EXCLUDED_NAMES
            and not path.name.endswith(EXCLUDED_SUFFIXES)
        )
    return sorted(set(paths), key=lambda path: path.relative_to(root).as_posix())


def project_version(root: Path) -> str:
    try:
        project = tomllib.loads(
            (root / "pyproject.toml").read_text(encoding="utf-8")
        ).get("project", {})
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    return str(project.get("version") or "")


def git_commit(root: Path) -> str:
    if not (root / ".git").exists():
        return ""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def build_identity(root: Path, source_root: Path | None = None) -> dict[str, Any]:
    resolved = root.resolve()
    files = {
        path.relative_to(resolved).as_posix(): sha256_file(path)
        for path in runtime_files(resolved)
    }
    tree_payload = json.dumps(
        files,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    source = (source_root or resolved).resolve()
    return {
        "kind": "gtm_skill_runtime_identity",
        "schema_version": 1,
        "project_version": project_version(resolved),
        "runtime_tree_sha256": hashlib.sha256(tree_payload).hexdigest(),
        "runtime_file_count": len(files),
        "source_git_commit": git_commit(source),
        "files": files,
    }


def write_manifest(
    root: Path,
    source_root: Path | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    identity = build_identity(root, source_root)
    target = output or root / MANIFEST_NAME
    target.write_text(
        json.dumps(identity, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return identity


def verify_identity(
    expected_root: Path,
    actual_root: Path,
) -> tuple[dict[str, Any], list[str]]:
    expected = build_identity(expected_root)
    actual = build_identity(actual_root)
    errors: list[str] = []
    expected_files = expected["files"]
    actual_files = actual["files"]
    missing = sorted(set(expected_files) - set(actual_files))
    unexpected = sorted(set(actual_files) - set(expected_files))
    changed = sorted(
        path
        for path in set(expected_files) & set(actual_files)
        if expected_files[path] != actual_files[path]
    )
    if missing:
        errors.append("runtime files missing from actual skill: " + ", ".join(missing))
    if unexpected:
        errors.append("unexpected runtime files in actual skill: " + ", ".join(unexpected))
    if changed:
        errors.append("runtime files differ: " + ", ".join(changed))

    declared_path = actual_root / MANIFEST_NAME
    declared: dict[str, Any] = {}
    if declared_path.is_file():
        try:
            raw = json.loads(declared_path.read_text(encoding="utf-8"))
            declared = raw if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError):
            errors.append(f"{MANIFEST_NAME} is not valid JSON")
        if declared and (
            declared.get("runtime_tree_sha256") != actual.get("runtime_tree_sha256")
            or declared.get("files") != actual.get("files")
        ):
            errors.append(
                f"{MANIFEST_NAME} does not match the actual installed runtime tree"
            )
    report = {
        "kind": "gtm_skill_runtime_identity_verification",
        "schema_version": 1,
        "status": "pass" if not errors else "fail",
        "expected": {
            key: expected.get(key)
            for key in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "source_git_commit",
            )
        },
        "actual": {
            key: actual.get(key)
            for key in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "source_git_commit",
            )
        },
        "declared_manifest_present": declared_path.is_file(),
        "missing_files": missing,
        "unexpected_files": unexpected,
        "changed_files": changed,
        "errors": errors,
    }
    return report, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity_parser = subparsers.add_parser("identity")
    identity_parser.add_argument("--root", type=Path, default=Path.cwd())
    identity_parser.add_argument("--pretty", action="store_true")

    write_parser = subparsers.add_parser("write")
    write_parser.add_argument("--root", type=Path, default=Path.cwd())
    write_parser.add_argument("--source-root", type=Path)
    write_parser.add_argument("--output", type=Path)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("expected_root", type=Path)
    verify_parser.add_argument("actual_root", type=Path)
    verify_parser.add_argument("--pretty", action="store_true")

    args = parser.parse_args()
    if args.command == "identity":
        result = build_identity(args.root)
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2 if args.pretty else None,
            )
        )
        return 0
    if args.command == "write":
        result = write_manifest(args.root, args.source_root, args.output)
        print(
            json.dumps(
                {
                    "status": "written",
                    "runtime_tree_sha256": result["runtime_tree_sha256"],
                    "runtime_file_count": result["runtime_file_count"],
                }
            )
        )
        return 0

    report, errors = verify_identity(args.expected_root, args.actual_root)
    print(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
        )
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

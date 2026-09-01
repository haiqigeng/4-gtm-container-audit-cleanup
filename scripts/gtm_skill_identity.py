#!/usr/bin/env python3
"""Build and verify a deterministic identity for the runnable skill tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

MANIFEST_NAME = ".skill-build-manifest.json"
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
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


def git_dirty(root: Path) -> bool | None:
    """Return source worktree state without treating a bundle as a clean checkout."""

    if not (root / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            text=True,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return bool(result.stdout.strip())


def git_tracked_files(root: Path) -> set[str] | None:
    """Return repository-relative tracked paths for a source checkout."""

    if not (root / ".git").exists():
        return None
    try:
        output = subprocess.check_output(
            ["git", "ls-files", "-z"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return {value for value in output.split("\0") if value}


def clean_git_identity_errors(root: Path, actual: dict[str, Any]) -> list[str]:
    """Verify a manifest-free development checkout from Git itself."""

    if not git_commit(root):
        return ["no readable Git commit identifies this source checkout"]
    dirty = git_dirty(root)
    if dirty is not False:
        return ["the Git source checkout is dirty or its state cannot be verified"]
    tracked = git_tracked_files(root)
    if tracked is None:
        return ["Git tracked files cannot be read for this source checkout"]
    untracked_runtime = sorted(set(actual.get("files") or {}) - tracked)
    if untracked_runtime:
        return [
            "runtime files are not tracked by the clean Git checkout: "
            + ", ".join(untracked_runtime)
        ]
    return []


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
        "source_git_dirty": git_dirty(source),
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


def declared_identity_errors(
    root: Path,
    *,
    require_manifest: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    """Verify that the runnable tree exactly matches its release manifest."""

    actual = build_identity(root)
    manifest_path = root / MANIFEST_NAME
    errors: list[str] = []
    declared: dict[str, Any] = {}
    identity_basis = "declared_manifest"
    if not manifest_path.is_file():
        if require_manifest:
            git_errors = clean_git_identity_errors(root, actual)
            if git_errors:
                errors.append(
                    f"{MANIFEST_NAME} is missing and the source checkout cannot replace it: "
                    + "; ".join(git_errors)
                )
            else:
                identity_basis = "clean_git_checkout"
    else:
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            declared = raw if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError):
            errors.append(f"{MANIFEST_NAME} is not valid JSON")
        if declared:
            if declared.get("kind") != "gtm_skill_runtime_identity":
                errors.append(f"{MANIFEST_NAME} kind is invalid")
            if declared.get("schema_version") != 1:
                errors.append(f"{MANIFEST_NAME} schema_version must be 1")
            for field in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "files",
            ):
                if declared.get(field) != actual.get(field):
                    errors.append(
                        f"{MANIFEST_NAME} {field} does not match the actual runtime tree"
                    )
            if declared.get("source_git_dirty") is not False:
                errors.append(
                    f"{MANIFEST_NAME} records dirty or unverifiable source provenance"
                )
            if not GIT_COMMIT_RE.fullmatch(
                str(declared.get("source_git_commit") or "")
            ):
                errors.append(
                    f"{MANIFEST_NAME} source_git_commit must be one full Git commit SHA"
                )
            if (root / ".git").exists():
                if actual.get("source_git_dirty") is not False:
                    errors.append(
                        "the source checkout is dirty or its state cannot be verified"
                    )
                if declared.get("source_git_commit") != actual.get(
                    "source_git_commit"
                ):
                    errors.append(
                        f"{MANIFEST_NAME} source commit differs from the checkout"
                    )
    report = {
        "kind": "gtm_declared_runtime_identity_check",
        "schema_version": 1,
        "status": "pass" if not errors else "fail",
        "identity_basis": identity_basis,
        "manifest": str(manifest_path),
        "declared": {
            key: declared.get(key)
            for key in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "source_git_commit",
                "source_git_dirty",
            )
        },
        "actual": {
            key: actual.get(key)
            for key in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "source_git_commit",
                "source_git_dirty",
            )
        },
        "errors": errors,
    }
    return report, errors


def verify_identity(
    expected_root: Path,
    actual_root: Path,
) -> tuple[dict[str, Any], list[str]]:
    expected = build_identity(expected_root)
    actual = build_identity(actual_root)
    errors: list[str] = []
    source_errors = clean_git_identity_errors(expected_root, expected)
    if source_errors:
        errors.append(
            "expected source provenance is not a clean Git checkout: "
            + "; ".join(source_errors)
        )
    expected_commit = str(expected.get("source_git_commit") or "")
    if not GIT_COMMIT_RE.fullmatch(expected_commit):
        errors.append("expected source commit is not one full Git commit SHA")
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
    if not declared_path.is_file():
        errors.append(f"{MANIFEST_NAME} is missing from the actual skill package")
    else:
        try:
            raw = json.loads(declared_path.read_text(encoding="utf-8"))
            declared = raw if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError):
            errors.append(f"{MANIFEST_NAME} is not valid JSON")
        if declared:
            if declared.get("kind") != "gtm_skill_runtime_identity":
                errors.append(f"{MANIFEST_NAME} kind is invalid")
            if declared.get("schema_version") != 1:
                errors.append(f"{MANIFEST_NAME} schema_version must be 1")
            for field in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "files",
            ):
                if declared.get(field) != actual.get(field):
                    errors.append(
                        f"{MANIFEST_NAME} {field} does not match the actual package tree"
                    )
                if declared.get(field) != expected.get(field):
                    errors.append(
                        f"{MANIFEST_NAME} {field} is not bound to the expected source tree"
                    )
            if declared.get("source_git_commit") != expected_commit:
                errors.append(
                    f"{MANIFEST_NAME} source_git_commit is not bound to the expected source commit"
                )
            if not GIT_COMMIT_RE.fullmatch(
                str(declared.get("source_git_commit") or "")
            ):
                errors.append(
                    f"{MANIFEST_NAME} source_git_commit must be one full Git commit SHA"
                )
            if declared.get("source_git_dirty") is not False:
                errors.append(
                    f"{MANIFEST_NAME} records dirty or unverifiable source provenance"
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
                "source_git_dirty",
            )
        },
        "actual": {
            key: actual.get(key)
            for key in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "source_git_commit",
                "source_git_dirty",
            )
        },
        "declared_manifest_present": declared_path.is_file(),
        "declared": {
            key: declared.get(key)
            for key in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "source_git_commit",
                "source_git_dirty",
            )
        },
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

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--root", type=Path, default=Path.cwd())
    check_parser.add_argument("--pretty", action="store_true")

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
    if args.command == "check":
        report, errors = declared_identity_errors(args.root)
        print(
            json.dumps(
                report,
                ensure_ascii=False,
                indent=2 if args.pretty else None,
            )
        )
        return 1 if errors else 0

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

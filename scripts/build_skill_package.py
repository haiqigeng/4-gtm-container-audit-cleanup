#!/usr/bin/env python3
"""Build a clean, agent-neutral skill bundle without repository-only files."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from gtm_skill_identity import write_manifest

ROOT_FILES = ("SKILL.md", "LICENSE", "pyproject.toml")
ROOT_DIRECTORIES = ("agents", "references", "scripts")
EXCLUDED_NAMES = {
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".mypy_cache",
    "gtm_self_test.py",
    "check_release.py",
    "build_skill_package.py",
    "release_blocklist.txt",
}


def ignore(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name in EXCLUDED_NAMES or name.endswith((".pyc", ".pyo", ".tmp", ".bak"))
    }


def build(root: Path, output: Path) -> None:
    if output.exists():
        raise FileExistsError(f"Output already exists; choose an empty path: {output}")
    output.mkdir(parents=True)
    for filename in ROOT_FILES:
        shutil.copy2(root / filename, output / filename)
    for dirname in ROOT_DIRECTORIES:
        shutil.copytree(root / dirname, output / dirname, ignore=ignore)
    write_manifest(output, source_root=root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build(root, args.output)
    print(f"Skill package: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

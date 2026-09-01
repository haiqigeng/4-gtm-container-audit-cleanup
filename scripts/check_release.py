#!/usr/bin/env python3
"""Run dependency-free release checks for the GTM web-analyst skill."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

MAX_SKILL_LINES = 500
LONG_REFERENCE_LINES = 100
BLOCKLIST_FILE = "scripts/release_blocklist.txt"
REFERENCE_BRANCHES = (
    "references/01-skill",
    "references/02-commands",
    "references/03-rules",
)
SEMVER_TAG_PATTERN = re.compile(
    r"^v"
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
RELEASE_NOTE_HEADINGS = (
    "why this release matters",
    "what changed",
    "what users should do",
    "validation",
    "known limits",
)
PROHIBITED_ROOT_FILES = {
    "CHANGELOG.md",
    "INSTALLATION_GUIDE.md",
    "QUICK_REFERENCE.md",
}
GENERATED_ARTIFACT_DIRS = {
    "__pycache__": "Python cache directory",
    ".ruff_cache": "Ruff cache directory",
    ".pytest_cache": "pytest cache directory",
    ".mypy_cache": "mypy cache directory",
    ".venv": "local virtual environment",
    "venv": "local virtual environment",
    "htmlcov": "coverage report directory",
}
GENERATED_ARTIFACT_FILES = {
    ".coverage": "coverage data file",
}
TEXT_SUFFIXES = {".md", ".py", ".toml", ".yaml", ".yml", ".txt"}
ALLOWED_ROOT_ENTRIES = {
    ".git",
    ".gitattributes",
    ".github",
    ".gitignore",
    ".skill-build-manifest.json",
    "AGENTS.md",
    "LICENSE",
    "README.md",
    "SKILL.md",
    "agents",
    "gtm-container-audit-cleanup-evolution.md",
    "pyproject.toml",
    "references",
    "scripts",
    "tests",
}
COVERAGE_PROFILES = ("code-only", "release-complete")
CODE_ONLY_PYTHON_COVERAGE_MINIMUMS = {
    "scripts/build_skill_package.py": 75,
    "scripts/check_release.py": 32,
    "scripts/gtm_architecture_review.py": 73,
    "scripts/gtm_audit_contract.py": 78,
    "scripts/gtm_audit_package_build.py": 71,
    "scripts/gtm_audit_work_units.py": 77,
    "scripts/gtm_baseline_audit.py": 60,
    "scripts/gtm_canonical_record.py": 72,
    "scripts/gtm_canonical_scan.py": 88,
    "scripts/gtm_cleanroom_audit.py": 67,
    "scripts/gtm_configuration_facts.py": 46,
    "scripts/gtm_configuration_review.py": 63,
    "scripts/gtm_configuration_review_groups.py": 78,
    "scripts/gtm_consent_model.py": 84,
    "scripts/gtm_context_model.py": 66,
    "scripts/gtm_custom_code_extract.py": 59,
    "scripts/gtm_delivery_mapper.py": 66,
    "scripts/gtm_delivery_reviews.py": 7,
    "scripts/gtm_fixed_point.py": 66,
    "scripts/gtm_lib.py": 68,
    "scripts/gtm_obligation_ledger.py": 73,
    "scripts/gtm_operation_model.py": 70,
    "scripts/gtm_operational_review.py": 47,
    "scripts/gtm_optimization_facts.py": 86,
    "scripts/gtm_privacy.py": 76,
    "scripts/gtm_projection_review.py": 69,
    "scripts/gtm_reasoning_identity.py": 88,
    "scripts/gtm_reconciliation.py": 66,
    "scripts/gtm_relationships.py": 69,
    "scripts/gtm_requirement_evidence.py": 13,
    "scripts/gtm_scan_assurance.py": 84,
    "scripts/gtm_self_test.py": 80,
    "scripts/gtm_shared_facts.py": 67,
    "scripts/gtm_skill_identity.py": 51,
    "scripts/gtm_source_model.py": 86,
    "scripts/gtm_target_synthesis.py": 76,
    "scripts/gtm_vendor_registry.py": 64,
}
RELEASE_COMPLETE_COVERAGE_OVERRIDES = {
    "scripts/gtm_delivery_mapper.py": 70,
    "scripts/gtm_delivery_reviews.py": 70,
    "scripts/gtm_reasoning_identity.py": 93,
    "scripts/gtm_self_test.py": 85,
}
TOTAL_COVERAGE_MINIMUMS = {
    "code-only": 65.0,
    "release-complete": 66.0,
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def coverage_profile_minimums(profile: str) -> tuple[float, dict[str, int]]:
    if profile not in COVERAGE_PROFILES:
        raise ValueError(f"unknown coverage profile: {profile}")
    minimums = dict(CODE_ONLY_PYTHON_COVERAGE_MINIMUMS)
    if profile == "release-complete":
        minimums.update(RELEASE_COMPLETE_COVERAGE_OVERRIDES)
    return TOTAL_COVERAGE_MINIMUMS[profile], minimums


def normalized_coverage_path(root: Path, value: str) -> str:
    rendered = value.replace("\\", "/")
    path = Path(rendered)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return rendered
    while rendered.startswith("./"):
        rendered = rendered[2:]
    return rendered


def python_trust_boundary_coverage_report(
    root: Path,
    payload: dict[str, Any],
    *,
    profile: str,
    total_minimum: float | None = None,
    module_minimums: dict[str, int] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Validate exact, branch-aware coverage of the Python trust boundary."""

    configured_total, configured_modules = coverage_profile_minimums(profile)
    required_total = configured_total if total_minimum is None else total_minimum
    required_modules = configured_modules if module_minimums is None else module_minimums
    expected = {
        path.relative_to(root).as_posix()
        for path in (root / "scripts").rglob("*.py")
        if path.is_file() and "__pycache__" not in path.parts
    }
    errors: list[str] = []
    threshold_paths = set(required_modules)
    if threshold_paths != expected:
        missing_thresholds = sorted(expected - threshold_paths)
        stale_thresholds = sorted(threshold_paths - expected)
        if missing_thresholds:
            errors.append(
                "Python trust-boundary coverage thresholds are missing: "
                + ", ".join(missing_thresholds)
            )
        if stale_thresholds:
            errors.append(
                "Python trust-boundary coverage thresholds are stale: "
                + ", ".join(stale_thresholds)
            )

    meta = payload.get("meta")
    files = payload.get("files")
    totals = payload.get("totals")
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True:
        errors.append("coverage evidence is not branch-aware")
    if not isinstance(files, dict):
        errors.append("coverage evidence has no file map")
        files = {}
    if not isinstance(totals, dict):
        errors.append("coverage evidence has no totals")
        totals = {}

    measured: dict[str, dict[str, Any]] = {}
    for raw_path, value in files.items():
        path = normalized_coverage_path(root, str(raw_path))
        if path in measured:
            errors.append(f"coverage evidence repeats Python path: {path}")
            continue
        measured[path] = value if isinstance(value, dict) else {}
    measured_paths = set(measured)
    missing_files = sorted(expected - measured_paths)
    unexpected_files = sorted(measured_paths - expected)
    if missing_files:
        errors.append(
            "trust-boundary Python files missing from coverage: "
            + ", ".join(missing_files)
        )
    if unexpected_files:
        errors.append(
            "unexpected Python files changed the coverage denominator: "
            + ", ".join(unexpected_files)
        )

    total_coverage = totals.get("percent_covered")
    if not isinstance(total_coverage, (int, float)) or isinstance(total_coverage, bool):
        errors.append("coverage evidence has no numeric total percentage")
        total_coverage = 0.0
    if total_coverage < required_total:
        errors.append(
            f"complete trust-boundary coverage {total_coverage:.2f}% is below "
            f"the {profile} minimum {required_total:.2f}%"
        )
    if not isinstance(totals.get("num_branches"), int) or totals.get("num_branches", 0) <= 0:
        errors.append("coverage evidence contains no measured branches")

    module_coverage: dict[str, float] = {}
    for path in sorted(expected & measured_paths & threshold_paths):
        summary = measured[path].get("summary")
        if not isinstance(summary, dict):
            errors.append(f"{path}: coverage summary is missing")
            continue
        percentage = summary.get("percent_covered")
        if not isinstance(percentage, (int, float)) or isinstance(percentage, bool):
            errors.append(f"{path}: coverage percentage is missing")
            continue
        module_coverage[path] = float(percentage)
        minimum = required_modules[path]
        if percentage < minimum:
            errors.append(
                f"{path}: branch-aware coverage {percentage:.2f}% is below "
                f"the {profile} minimum {minimum}%"
            )

    report = {
        "kind": "gtm_complete_python_coverage_gate",
        "schema_version": 1,
        "status": "pass" if not errors else "fail",
        "profile": profile,
        "trust_boundary_python_files": len(expected),
        "measured_trust_boundary_python_files": len(expected & measured_paths),
        "total_percent_covered": round(float(total_coverage), 4),
        "minimum_total_percent_covered": required_total,
        "total_branches": totals.get("num_branches", 0),
        "covered_branches": totals.get("covered_branches", 0),
        "module_percent_covered": module_coverage,
        "errors": errors,
    }
    return report, errors


def check_coverage_json(
    root: Path, path: Path, profile: str
) -> tuple[dict[str, Any], list[str]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error = f"coverage JSON cannot be read: {path}: {exc}"
        return {
            "kind": "gtm_complete_python_coverage_gate",
            "schema_version": 1,
            "status": "fail",
            "profile": profile,
            "errors": [error],
        }, [error]
    if not isinstance(raw, dict):
        error = f"coverage JSON root must be an object: {path}"
        return {
            "kind": "gtm_complete_python_coverage_gate",
            "schema_version": 1,
            "status": "fail",
            "profile": profile,
            "errors": [error],
        }, [error]
    return python_trust_boundary_coverage_report(root, raw, profile=profile)


def text_files(root: Path) -> list[Path]:
    paths = []
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {
            ".gitattributes",
            ".gitignore",
            "LICENSE",
        }:
            paths.append(path)
    return sorted(paths)


def parse_frontmatter(skill_path: Path) -> tuple[dict[str, str], list[str]]:
    text = skill_path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, ["SKILL.md frontmatter is missing"]
    try:
        _, raw, _ = text.split("---", 2)
    except ValueError:
        return {}, ["SKILL.md frontmatter is not closed"]

    values: dict[str, str] = {}
    errors = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            errors.append(f"Invalid frontmatter line: {line}")
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip().strip('"')

    keys = list(values)
    if keys != ["name", "description"]:
        errors.append(f"Frontmatter keys must be name, description; found {keys}")
    if values.get("name") != "gtm-container-audit-cleanup":
        errors.append("Skill name must be gtm-container-audit-cleanup")
    if not values.get("description"):
        errors.append("Skill description is empty")
    return values, errors


def referenced_resources(root: Path) -> tuple[set[str], list[str]]:
    refs: set[str] = set()
    missing: list[str] = []
    pattern = re.compile(r"((?:references|scripts)/[A-Za-z0-9_./*-]+)")
    for path in text_files(root):
        content = path.read_text(encoding="utf-8")
        for match in pattern.finditer(content):
            rel = match.group(1).rstrip(".,;:)")
            target = root / rel
            if rel.endswith("/") or target.is_dir():
                if target.is_dir():
                    refs.update(
                        child.relative_to(root).as_posix()
                        for child in target.rglob("*")
                        if child.is_file()
                    )
                continue
            if "*" in rel:
                matches = sorted(path for path in root.glob(rel) if path.is_file())
                if not matches:
                    missing.append(
                        f"{path.relative_to(root)} references unmatched wildcard {rel}"
                    )
                refs.update(
                    match.relative_to(root).as_posix() for match in matches
                )
                continue
            refs.add(rel)
            if not target.exists():
                missing.append(f"{path.relative_to(root)} references missing {rel}")
    return refs, missing


def imported_scripts(root: Path) -> set[str]:
    imports: set[str] = set()
    pattern = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)")
    for path in sorted((root / "scripts").glob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = pattern.match(line)
            if not match:
                continue
            candidate = root / "scripts" / f"{match.group(1)}.py"
            if candidate.exists():
                imports.add(candidate.relative_to(root).as_posix())
    return imports


def release_blocklist(root: Path) -> list[str]:
    path = root / BLOCKLIST_FILE
    if not path.is_file():
        raise FileNotFoundError(f"Missing required release blocklist: {BLOCKLIST_FILE}")
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            patterns.append(value)
    if not patterns:
        raise ValueError(f"Required release blocklist is empty: {BLOCKLIST_FILE}")
    return patterns


def check_orphan_resources(root: Path, referenced: set[str]) -> list[str]:
    errors = []
    imported = imported_scripts(root)
    exempt = {
        "scripts/check_release.py",
        "scripts/gtm_self_test.py",
    }
    routed = referenced | imported | exempt

    for path in sorted((root / "references").rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".md", ".toml"}:
            continue
        rel = path.relative_to(root).as_posix()
        if rel not in routed:
            errors.append(f"{rel} is not referenced, imported, or explicitly exempted")
    for path in sorted((root / "scripts").glob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel not in routed:
            errors.append(f"{rel} is not referenced, imported, or explicitly exempted")
    return errors


def check_reference_branches(root: Path) -> list[str]:
    errors = []
    for rel in REFERENCE_BRANCHES:
        if not (root / rel).is_dir():
            errors.append(f"Missing required reference branch: {rel}")

    allowed_prefixes = tuple(f"{rel}/" for rel in REFERENCE_BRANCHES)
    for path in sorted((root / "references").rglob("*.md")):
        rel = path.relative_to(root).as_posix()
        if not rel.startswith(allowed_prefixes):
            errors.append(f"{rel} is outside the required reference branches")
    return errors


def git_ls_files(root: Path) -> set[str]:
    if not (root / ".git").exists():
        return set()
    try:
        output = subprocess.check_output(
            ["git", "ls-files"], cwd=root, text=True, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("Unable to verify tracked release resources with git ls-files") from exc
    return set(output.splitlines())


def check_reference_navigation(root: Path) -> list[str]:
    errors = []
    for path in sorted((root / "references").rglob("*.md")):
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > LONG_REFERENCE_LINES and "## Contents" not in lines[:25]:
            errors.append(f"{path.relative_to(root)} has {len(lines)} lines and no ## Contents")
    return errors


def check_forbidden_skill_files(root: Path) -> list[str]:
    errors = []
    for filename in sorted(PROHIBITED_ROOT_FILES):
        if (root / filename).exists():
            errors.append(
                f"{filename} is not allowed in this repo; keep operational guidance in SKILL.md, references/, or README.md"
            )
    return errors


def check_generated_artifacts(root: Path) -> list[str]:
    errors = []
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts:
            continue
        if path.is_dir() and path.name in GENERATED_ARTIFACT_DIRS:
            errors.append(
                f"Generated {GENERATED_ARTIFACT_DIRS[path.name]} must be removed: "
                f"{path.relative_to(root)}"
            )
        elif path.is_file() and path.name in GENERATED_ARTIFACT_FILES:
            errors.append(
                f"Generated {GENERATED_ARTIFACT_FILES[path.name]} must be removed: "
                f"{path.relative_to(root)}"
            )
    for path in sorted(root.rglob("*.pyc")):
        if ".git" in path.parts:
            continue
        errors.append(f"Generated Python bytecode file must be removed: {path.relative_to(root)}")
    return errors


def check_repository_layout(root: Path) -> list[str]:
    errors = []
    for path in root.iterdir():
        if path.name in GENERATED_ARTIFACT_DIRS or path.name in GENERATED_ARTIFACT_FILES:
            continue
        if path.is_dir() and path.name.endswith(".egg-info"):
            continue
        if path.name not in ALLOWED_ROOT_ENTRIES:
            errors.append(f"Unexpected top-level repository entry: {path.name}")
    if not (root / "LICENSE").is_file():
        errors.append("LICENSE is required for the public reusable skill repository")
    if not (root / ".github" / "workflows" / "ci.yml").is_file():
        errors.append("Missing .github/workflows/ci.yml")
    return errors


def check_patterns(root: Path, name: str, patterns: list[str]) -> list[str]:
    errors = []
    compiled = [(pattern, re.compile(pattern, re.I)) for pattern in patterns]
    for path in text_files(root):
        if path.relative_to(root).as_posix() == BLOCKLIST_FILE:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for label, pattern in compiled:
                if pattern.search(line):
                    errors.append(f"{name}: {path.relative_to(root)}:{lineno}: {label}")
    return errors


def check_py_compile(root: Path) -> list[str]:
    errors = []
    for path in sorted((root / "scripts").glob("*.py")):
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except SyntaxError as exc:
            errors.append(
                f"syntax check failed for {path.relative_to(root)}:{exc.lineno}: {exc.msg}"
            )
    return errors


def check_production_test_imports(root: Path) -> list[str]:
    errors: list[str] = []
    pattern = re.compile(r"^\s*(?:from|import)\s+tests?(?:\.|\s|$)", re.M)
    for path in sorted((root / "scripts").glob("*.py")):
        if pattern.search(path.read_text(encoding="utf-8")):
            errors.append(
                f"{path.relative_to(root)} imports repository test code and will fail "
                "in the clean runtime bundle"
            )
    return errors


def check_release_tag(tag: str | None) -> list[str]:
    if not tag:
        return []
    if SEMVER_TAG_PATTERN.fullmatch(tag):
        return []
    return [f"Release tag must use vMAJOR.MINOR.PATCH semantic versioning, found {tag!r}"]


def check_project_version(root: Path, tag: str | None) -> list[str]:
    if not tag or not SEMVER_TAG_PATTERN.fullmatch(tag):
        return []
    path = root / "pyproject.toml"
    try:
        project = tomllib.loads(path.read_text(encoding="utf-8")).get("project", {})
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [f"Unable to read project version from {path}: {exc}"]
    version = project.get("version")
    expected = tag[1:]
    if version != expected:
        return [f"pyproject.toml project.version must match {expected!r}, found {version!r}"]
    return []


def check_clean_tagged_checkout(root: Path, tag: str | None) -> list[str]:
    """A release tag may only identify a clean, fully committed source tree."""

    if not tag:
        return []
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ["Tagged release checkout cleanliness could not be verified"]
    if result.stdout.strip():
        return ["Tagged release checkout must be clean and fully committed"]
    return []


def check_release_notes(path: Path | None) -> list[str]:
    if path is None:
        return []
    if not path.exists():
        return [f"Release notes file does not exist: {path}"]

    text = path.read_text(encoding="utf-8")
    normalized = text.lower()
    errors = []
    for heading in RELEASE_NOTE_HEADINGS:
        pattern = re.compile(rf"^#+\s+{re.escape(heading)}\s*$", re.I | re.M)
        if not pattern.search(text):
            errors.append(f"Release notes missing heading: {heading.title()}")

    bullets = len(re.findall(r"(?m)^\s*[-*]\s+\S+", text))
    if bullets < 3:
        errors.append("Release notes should include at least three readable bullets")
    if "validation" in normalized and "python" in normalized and "not run" in normalized:
        return errors
    if "validation" in normalized and not re.search(
        r"\b(pass|passed|not run|blocked)\b", normalized
    ):
        errors.append("Validation section should state passed or blocked checks")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-untracked",
        action="store_true",
        help="Do not fail when referenced resources are not tracked by git.",
    )
    parser.add_argument(
        "--tag",
        help="Validate a proposed vMAJOR.MINOR.PATCH tag and project-version match.",
    )
    parser.add_argument(
        "--release-notes",
        type=Path,
        help="Validate human-readable release notes before publishing.",
    )
    parser.add_argument(
        "--coverage-json",
        type=Path,
        help="Fail closed against branch-aware coverage JSON for the full Python tree.",
    )
    parser.add_argument(
        "--coverage-profile",
        choices=COVERAGE_PROFILES,
        default="code-only",
        help="Coverage baseline expected from the test environment.",
    )
    args = parser.parse_args()

    root = repo_root()
    errors: list[str] = []

    _, frontmatter_errors = parse_frontmatter(root / "SKILL.md")
    errors.extend(frontmatter_errors)

    skill_lines = (root / "SKILL.md").read_text(encoding="utf-8").splitlines()
    if len(skill_lines) > MAX_SKILL_LINES:
        errors.append(f"SKILL.md has {len(skill_lines)} lines; max is {MAX_SKILL_LINES}")

    refs, missing_refs = referenced_resources(root)
    errors.extend(missing_refs)
    errors.extend(check_reference_branches(root))
    errors.extend(check_repository_layout(root))
    errors.extend(check_orphan_resources(root, refs))

    try:
        tracked = git_ls_files(root)
    except RuntimeError as exc:
        tracked = set()
        errors.append(str(exc))
    if tracked and not args.allow_untracked:
        untracked_refs = sorted(ref for ref in refs if ref not in tracked)
        if untracked_refs:
            errors.append("Referenced resources are untracked: " + ", ".join(untracked_refs))

    errors.extend(check_reference_navigation(root))
    errors.extend(check_forbidden_skill_files(root))
    errors.extend(check_generated_artifacts(root))
    try:
        blocklist = release_blocklist(root)
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    else:
        errors.extend(check_patterns(root, "blocklist", blocklist))
    errors.extend(check_py_compile(root))
    errors.extend(check_production_test_imports(root))
    errors.extend(check_release_tag(args.tag))
    errors.extend(check_project_version(root, args.tag))
    errors.extend(check_clean_tagged_checkout(root, args.tag))
    errors.extend(check_release_notes(args.release_notes))
    if args.coverage_json is not None:
        coverage_report, coverage_errors = check_coverage_json(
            root,
            args.coverage_json,
            args.coverage_profile,
        )
        errors.extend(coverage_errors)
        print(json.dumps(coverage_report, ensure_ascii=False, sort_keys=True))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"Release check: FAIL ({len(errors)} error(s))")
        return 1

    print(
        f"Release check: PASS ({len(refs)} referenced resources, SKILL.md {len(skill_lines)} lines)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

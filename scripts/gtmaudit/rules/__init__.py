"""Deterministic rule catalog: targeted candidates with exact objects, never verdicts.

Emissions of one rule are grouped into one candidate (one shared judgment with local
exceptions), except cluster rules where each emission is its own group of objects.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..records import SEVERITIES
from ..source import Model
from . import consent_privacy, families, google, structure, vendors_code

MODULES = (consent_privacy, google, vendors_code, structure, families)
DOMAINS = {
    "D1": "Consent, privacy and security",
    "D2": "Google measurement",
    "D3": "Vendors, templates and custom code",
    "D4": "Structure and maintainability",
    "D5": "Families, duplicates and target design",
}
CLUSTER_RULES = set().union(*(m.CLUSTERS for m in MODULES))


@dataclass
class Item:
    title: str
    objects: list[str]
    detail: str = ""


@dataclass
class Candidate:
    rule: str
    domain: str
    area: str
    severity: str
    title: str
    objects: list[str]
    items: list[Item] = field(default_factory=list)
    id: str = ""


@dataclass
class Result:
    candidates: list[Candidate] = field(default_factory=list)
    facts: dict[str, object] = field(default_factory=dict)


def registry() -> dict[str, tuple[str, str, str, str]]:
    """rule id -> (domain, area, default severity, rationale)."""
    out: dict[str, tuple[str, str, str, str]] = {}
    for module in MODULES:
        if not module.CLUSTERS <= set(module.RULES):
            raise ValueError(f"{module.__name__}: CLUSTERS names rules it does not define")
        for rule, spec in module.RULES.items():
            if rule in out:
                raise ValueError(f"Duplicate rule id {rule}")
            out[rule] = spec
    return out


def run(model: Model) -> Result:
    rules = registry()
    order = {s: i for i, s in enumerate(SEVERITIES)}
    result = Result()
    emissions: list[tuple[str, str, str, Item]] = []
    seen: set[tuple[str, tuple[str, ...], str]] = set()

    def emit(rule: str, title: str, objects: list[str], detail: str = "", severity: str | None = None) -> None:
        sig = (rule, tuple(sorted(objects)), title)
        if sig not in seen:
            seen.add(sig)
            emissions.append((rule, severity or rules[rule][2], title, Item(title, sorted(set(objects)), detail)))

    def fact(name: str, value: object) -> None:
        result.facts[name] = value

    for module in MODULES:
        module.run(model, emit, fact)

    grouped: dict[str, Candidate] = {}
    for rule, severity, title, item in emissions:
        domain, area, _, rationale = rules[rule]
        if rule in CLUSTER_RULES:
            result.candidates.append(Candidate(rule, domain, area, severity, title, item.objects, [item]))
            continue
        c = grouped.get(rule)
        if c is None:
            c = grouped[rule] = Candidate(rule, domain, area, severity, rationale, [], [])
            result.candidates.append(c)
        c.items.append(item)
        c.objects = sorted(set(c.objects) | set(item.objects))
        if order.get(severity, 9) < order.get(c.severity, 9):
            c.severity = severity
    for c in result.candidates:
        if c.rule not in CLUSTER_RULES and len(c.items) > 1:
            c.title = f"{rules[c.rule][3]} ({len(c.items)} occurrences)"
    result.candidates.sort(key=lambda c: (c.domain, order.get(c.severity, 9), c.rule, c.objects))
    for index, c in enumerate(result.candidates, 1):
        c.id = f"C-{index:03d}"
    return result


def as_dicts(candidates: list[Candidate]) -> list[dict]:
    return [asdict(c) for c in candidates]

"""Record contract, reader texts and the live projection (decisions, verdict history)."""


import pytest
from conftest import finding, operation

from gtmaudit.records import RecordError, Store


def test_record_validation(tmp_path, model):
    store = Store(tmp_path)
    known = set(model.objects)
    with pytest.raises(RecordError):
        store.append("D4", [finding(basis="")], known, set())
    with pytest.raises(RecordError):
        store.append("D4", [finding(readiness="ready", operations=[])], known, set())
    with pytest.raises(RecordError):
        store.append("D4", [finding(objects=["tag:999"])], known, set())
    with pytest.raises(RecordError):
        store.append("D1", [finding()], known, set())
    store.append("D4", [finding(), operation()], known, set())
    assert store.append("D4", [finding(title="Cart tag capped once per page")], known, set()) == [
        "replaced finding D4-F01"]
    with pytest.raises(RecordError):
        store.append("D2", [{**finding(), "id": "D4-F01"}], known, set())
    with pytest.raises(RecordError):
        store.append("D4", [{"type": "decision", "action": "reject", "ids": ["D4-F01"], "reason": "x"}], known, set())
    with pytest.raises(RecordError, match="unknown field"):
        store.append("D4", [finding(confidence="High")], known, set())


@pytest.mark.parametrize("record", [
    {"situation": "Same cap as D2-F03."}, {"impact": "Confirms C-012."}, {"title": "A08 cap"},
    {"recommendation": "Set parameter:eventName.value."}, {"situation": "tag191 has tagFiringOption ONCE_PER_LOAD."}])
def test_reader_texts_use_gtm_terms(tmp_path, model, record):
    store, known = Store(tmp_path), set(model.objects)
    with pytest.raises(RecordError, match="internal notation"):
        store.append("D4", [finding(**record)], known, set())
    with pytest.raises(RecordError, match="internal notation"):
        store.append("D4", [operation(rollback="Undo D4-OP01.")], known, set())
    with pytest.raises(RecordError, match="internal notation"):
        store.append("INT", [{"type": "summary", "target": "t", "naming": "n", "limits": "See A26."}], known, set())
    assert store.append("D4", [finding(situation="tag:4 and trigger:11 fire on every add-to-cart.")], known, set())


def test_finalize_applies_decisions_and_verdicts(model, tmp_path):
    from gtmaudit.final import finalize
    store = Store(tmp_path)
    known = set(model.objects)
    store.append("D4", [finding(), operation()], known, set())
    store.append("VER", [{"type": "verdict", "target": "D4-F01", "verdict": "downgrade", "reason": "r",
                          "change": "Medium"}], known, set())
    result = finalize(model, store, [], {})
    assert any("not yet handled" in e for e in result["errors"])
    assert any("summary" in e for e in result["errors"])
    store.append("INT", [
        {"type": "decision", "action": "replace", "ids": ["D4-F01"], "reason": "downgraded",
         "record": finding(id="INT-F01", severity="Medium", operations=["D4-OP01"])},
        {"type": "summary", "target": "t", "naming": "n", "limits": "l"}], known, set())
    result = finalize(model, store, [], {})
    assert result["errors"] == [], result["errors"]
    assert [f["id"] for f in result["findings"]] == ["INT-F01"]
    assert result["operations"][0]["findings"] == ["INT-F01"]
    store.append("INT", [{"type": "decision", "action": "reject", "ids": ["INT-F01"], "reason": "not supported"}],
                 known, set())
    assert any("supports no remaining finding" in e for e in finalize(model, store, [], {})["errors"])


def test_verdict_history_is_read_one_way(model, tmp_path):
    from gtmaudit.final import effective, verdict_problems
    store, known = Store(tmp_path), set(model.objects)
    store.append("D4", [finding(), operation()], known, set())
    store.append("INT", [{"type": "decision", "action": "replace", "ids": ["D4-F01"], "reason": "r",
                          "record": finding(id="INT-F01")}], known, set())
    verdicts = [{"type": "verdict", "target": "D4-F01", "verdict": "fix", "reason": "r", "change": "c"},
                {"type": "verdict", "target": "D4-OP01", "verdict": "fix", "reason": "r", "change": "c"},
                {"type": "verdict", "target": "D9-F99", "verdict": "confirm", "reason": "r"}]
    unknown, unhandled = verdict_problems(effective(store), verdicts)
    assert [u.split()[2] for u in unknown] == ["D9-F99,"]
    assert len(unhandled) == 1 and "D4-OP01" in unhandled[0]


def test_every_object_field_has_a_gtm_label():
    from gtmaudit.source import OBJECT_FIELDS
    from gtmaudit.steps import FIELDS
    assert set(FIELDS) == set(OBJECT_FIELDS)

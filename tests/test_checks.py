"""Judging operations: applicability, consent routes, payloads and readiness."""

import json

from conftest import container, finding, operation, p

from gtmaudit import checks, source
from gtmaudit.records import Store


def test_applicability_flags_new_collection_paths_only(tmp_path):
    from gtmaudit import source
    data = container()
    data["containerVersion"]["tag"][2]["paused"] = True  # tag:3, an ungated Meta base tag
    path = tmp_path / "a.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    model = source.load(path)
    ready = {"readiness": "ready"}
    activate = {**operation(id="D3-OP05", actions=[{"do": "unpause", "object": "tag:3"}]), **ready}
    broaden = {**operation(id="D4-OP07", actions=[
        {"do": "set", "object": "trigger:11", "path": "customEventFilter", "value": []}]), **ready}
    consolidate = {**operation(id="D5-OP04", actions=[
        {"do": "remap", "from": "trigger:13", "to": "trigger:10"}, {"do": "delete", "object": "trigger:13"}]), **ready}
    results = checks.applicability(model, [activate, broaden, consolidate])
    assert any("tag:3" in e for e in results["D3-OP05"]["errors"])
    assert results["D5-OP04"]["errors"] == []
    assert not any("route of tag:4" in e for e in results["D4-OP07"]["errors"])  # tag:4 keeps its blocker


def test_inert_code_that_starts_executing_is_a_new_path(tmp_path):
    from gtmaudit import source
    data = container()
    cv = data["containerVersion"]
    cv["tag"].append({"tagId": "8", "name": "Vendor - inert", "type": "html", "firingTriggerId": ["10"],
                      "parameter": [p("html", "fbq('track','Purchase');")]})
    path = tmp_path / "i.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    m = source.load(path)
    wrap = {**operation(id="D3-OP06", actions=[{"do": "set", "object": "tag:8", "path": "parameter:html.value",
                                                  "value": "<script>fbq('track','Purchase');</script>"}]),
            "readiness": "ready"}
    assert any("tag:8" in e for e in checks.applicability(m, [wrap])["D3-OP06"]["errors"])
    conditional = {**wrap, "readiness": "conditional"}
    result = checks.applicability(m, [conditional])["D3-OP06"]
    assert result["errors"] == [] and any("tag:8" in w for w in result["warnings"])


def test_ready_operations_have_no_preconditions(model):
    op = {**operation(preconditions="Rotate the credential first."), "readiness": "ready"}
    assert any("preconditions" in e for e in checks.applicability(model, [op])["D4-OP01"]["errors"])
    op["readiness"] = "conditional"
    assert checks.applicability(model, [op])["D4-OP01"]["errors"] == []


def test_ready_work_is_never_more_ready_than_what_it_relies_on(model, tmp_path):
    from gtmaudit.final import effective, work_problems
    store, known = Store(tmp_path), set(model.objects)
    open_value = {**finding(id="D2-F01", area="A20", objects=["variable:20"], operations=[]), "class": "evidence_limit",
                  "basis": "", "severity": "Medium", "readiness": "n/a",
                  "question": "Is ecommerce.value the order total before tax (keep) or after tax (change the source)?"}
    sends = operation(id="D2-OP01", findings=["D2-F02"], actions=[
        {"do": "add", "object": "tag:1", "path": "parameter:configSettingsTable.list",
         "value": {"type": "MAP", "map": [p("parameter", "order_value"), p("parameterValue", "{{DLV - value}}")]}}])
    after = operation(id="D2-OP02", findings=["D2-F03"], depends_on=["D4-OP01"])
    ready = {**finding(id="D2-F02", area="A17", operations=["D2-OP01"]), "readiness": "ready", "question": ""}
    store.append("D2", [open_value, ready, sends, {**ready, "id": "D2-F03", "operations": ["D2-OP02"]},
                        {**after, "actions": [{"do": "remove", "object": "tag:2", "path": "priority"}]}], known, set())
    store.append("D4", [finding(), operation()], known, set())
    problems = work_problems(model, effective(store), {})
    assert any("newly sends variable:20, whose meaning D2-F01 leaves open" in e for e in problems["D2-OP01"]["errors"])
    assert any("depends on D4-OP01, which waits for an answer" in e for e in problems["D2-OP02"]["errors"])
    assert not problems["D4-OP01"]["errors"]
    store.append("D4", [operation(findings=["D4-F01", "D4-F02"]),
                        {**finding(id="D4-F02"), "readiness": "ready", "question": ""}], known, set())
    shared = work_problems(model, effective(store), {})
    assert any("its change D4-OP01 waits for an answer (it also serves D4-F01)" in e for e in shared["D4-F02"]["errors"])


def test_payload_comparison_separates_shared_settings_from_new_values(model):
    rows = "parameter:eventSettingsTable.list"
    shared = operation(id="D2-OP01", actions=[
        {"do": "create", "layer": "variable", "ref": "new:variable:settings", "object": {
            "name": "GTES - purchase", "type": "gtes", "parameter": [{"type": "LIST", "key": "eventSettingsTable",
                "list": [{"type": "MAP", "map": [p("parameter", "value"), p("parameterValue", "{{DLV - value}}")]}]}]}},
        {"do": "set", "object": "tag:2", "path": "parameter:eventSettingsVariable.value", "value": "{{GTES - purchase}}"},
        {"do": "remove", "object": "tag:2", "path": rows + ".row:parameter=value"}])
    computed = operation(id="D2-OP02", actions=[
        {"do": "create", "layer": "variable", "ref": "new:variable:net", "object": {
            "name": "CJS - net value", "type": "jsm", "parameter": [p("javascript", "function(){return {{DLV - value}}*0.8}")]}},
        {"do": "add", "object": "tag:2", "path": rows,
         "value": {"type": "MAP", "map": [p("parameter", "net_value"), p("parameterValue", "{{CJS - net value}}")]}}])
    debug = operation(id="D2-OP03", actions=[
        {"do": "remove", "object": "tag:1", "path": "parameter:configSettingsTable.list.row:parameter=debug_mode"}])
    results = checks.applicability(model, [shared, computed, debug])
    assert "variable:20" not in results["D2-OP01"]["sends"]
    assert "variable:20" in results["D2-OP02"]["sends"]
    assert any("tag:2 stop sending debug_mode" in w for w in results["D2-OP03"]["warnings"])
    assert not any("stop sending" in w for w in results["D2-OP02"]["warnings"])


def test_an_exact_alias_sends_nothing_new(tmp_path):
    raw = container()
    raw["containerVersion"]["variable"].append({"variableId": "24", "name": "DLV - value copy", "type": "v",
                                                "parameter": [p("name", "ecommerce.value")]})
    export = tmp_path / "export.json"
    export.write_text(json.dumps(raw), encoding="utf-8")
    model = source.load(export)
    alias = operation(id="D4-OP01", actions=[{"do": "remap", "from": "variable:20", "to": "variable:24"}])
    other = operation(id="D4-OP02", actions=[{"do": "remap", "from": "variable:21", "to": "variable:23"}])
    results = checks.applicability(model, [alias, other])
    assert "variable:24" not in results["D4-OP01"]["sends"]
    assert "variable:23" in results["D4-OP02"]["sends"]

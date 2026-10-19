"""Applying operations: simulation, write ownership, paths and creates."""

import json

import pytest
from conftest import finding, operation, p

from gtmaudit import operations
from gtmaudit.records import RecordError, Store


def test_simulation_applies_and_detects(model):
    ok = operations.simulate(model, [operation()])
    assert ok["ok"] and ok["diff"]["tag:4"]["fields"] == ["tagFiringOption"]
    rename = operation(id="D4-OP02", actions=[{"do": "rename", "object": "variable:20", "name": "DLV - ecommerce.value"}])
    result = operations.simulate(model, [rename])
    assert result["ok"] and "{{DLV - ecommerce.value}}" in json.dumps(result["target"])
    conflict = operation(id="D4-OP03", actions=[{"do": "set", "object": "tag:4", "path": "tagFiringOption",
                                                  "value": "UNLIMITED"}])
    assert not operations.simulate(model, [operation(), conflict])["ok"]
    unblock = operation(id="D4-OP04", actions=[{"do": "set", "object": "tag:4", "path": "blockingTriggerId",
                                                 "value": []}])
    result = operations.simulate(model, [unblock])
    assert any("consent predicate" in e for e in result["errors"])
    delete_used = operation(id="D4-OP05", actions=[{"do": "delete", "object": "variable:20"}])
    assert not operations.simulate(model, [delete_used])["ok"]
    merge = operation(id="D5-OP01", actions=[{"do": "remap", "from": "trigger:13", "to": "trigger:10"},
                                              {"do": "delete", "object": "trigger:13"}])
    assert operations.simulate(model, [merge])["ok"]
    create = operation(id="D1-OP01", actions=[
        {"do": "create", "layer": "trigger", "ref": "new:trigger:block", "object": {
            "name": "Block - x", "type": "CUSTOM_EVENT", "customEventFilter": []}},
        {"do": "add", "object": "tag:3", "path": "blockingTriggerId", "value": "new:trigger:block"},
        {"do": "set", "object": "tag:2", "path": "parameter:eventSettingsTable.list.row:parameter=value"
                                                  ".map:parameterValue.value", "value": "{{DLV - order}}"}])
    result = operations.simulate(model, [create])
    assert result["ok"], result["errors"]
    assert result["created"] == ["trigger:14"]


def test_protected_objects_and_consent_approvals(model):
    assert any("protected" in e for e in operations.simulate(model, [operation()], {"do_not_touch": ["tag:4"]})["errors"])
    drop_ga4_blocker = operation(id="D1-OP02", actions=[{"do": "set", "object": "tag:2", "path": "blockingTriggerId",
                                                          "value": []}])
    assert not operations.simulate(model, [drop_ga4_blocker])["ok"]
    approved = {"consent_mode_destinations": ["G-ABCDEF1234"]}
    assert operations.simulate(model, [drop_ga4_blocker], approved)["ok"]


def test_create_payloads_for_every_layer_pass_add_and_simulation(model, tmp_path):
    store = Store(tmp_path)
    creates = operation(id="D5-OP01", findings=["D5-F01"], actions=[
        {"do": "create", "layer": "folder", "ref": "new:folder:ga4", "object": {"name": "GA4"}},
        {"do": "create", "layer": "variable", "ref": "new:variable:purchase-settings", "object": {
            "name": "GTES - purchase", "type": "gtes", "parentFolderId": "new:folder:ga4",
            "parameter": [{"type": "LIST", "key": "eventSettingsTable", "list": []}]}},
        {"do": "create", "layer": "trigger", "ref": "new:trigger:cart", "object": {
            "name": "CE - cart", "type": "CUSTOM_EVENT", "customEventFilter": []}},
        {"do": "create", "layer": "tag", "ref": "new:tag:cart", "object": {
            "name": "GA4 - add_to_cart", "type": "gaawe", "firingTriggerId": ["new:trigger:cart"],
            "blockingTriggerId": ["12"], "parameter": [{"type": "TEMPLATE", "key": "eventName", "value": "add_to_cart"}]}},
        {"do": "set", "object": "tag:2", "path": "parameter:eventSettingsVariable.value",
         "value": "{{GTES - purchase}}"}])
    store.append("D5", [finding(id="D5-F01", area="A05", operations=["D5-OP01"]), creates], set(model.objects), set())
    saved = [r for r in store.read("D5") if r["type"] == "operation"]
    result = operations.simulate(model, saved)
    assert result["ok"], result["errors"]
    assert sorted(result["created"]) == ["folder:31", "tag:7", "trigger:14", "variable:24"]
    for bad in ({"do": "create", "layer": "tag", "ref": "new:tag:x", "object": "tag:1"},
                {"do": "create", "layer": "zone", "ref": "new:zone:x", "object": {"name": "z"}},
                {"do": "create", "layer": "tag", "ref": "tag:9", "object": {"name": "x"}},
                {"do": "set", "object": {"name": "x"}, "path": "name", "value": "y"}):
        with pytest.raises(RecordError):
            store.append("D5", [operation(id="D5-OP02", findings=["D5-F01"], actions=[bad])], set(model.objects), set())


def test_dotted_row_values_in_paths(model):
    rows = "parameter:configSettingsTable.list.row:parameter=user_data.email_address"
    add_row = operation(id="D1-OP03", findings=["D4-F01"], actions=[
        {"do": "add", "object": "tag:1", "path": "parameter:configSettingsTable.list", "value": {
            "type": "MAP", "map": [{"type": "TEMPLATE", "key": "parameter", "value": "user_data.email_address"},
                                   {"type": "TEMPLATE", "key": "parameterValue", "value": "{{DLV - order}}"}]}},
        {"do": "set", "object": "tag:1", "path": rows + ".map:parameterValue.value", "value": "{{DLV - value}}"}])
    result = operations.simulate(model, [add_row])
    assert result["ok"], result["errors"]
    remove_row = operation(id="D1-OP04", findings=["D4-F01"], depends_on=["D1-OP03"],
                           actions=[{"do": "remove", "object": "tag:1", "path": rows}])
    assert operations.simulate(model, [add_row, remove_row])["ok"]


def test_writes_conflict_only_on_the_same_field_or_row(model):
    def row(name):
        return {"type": "MAP", "map": [p("parameter", name), p("parameterValue", "x")]}
    table = "parameter:eventSettingsTable.list"
    event_id = operation(id="D2-OP01", actions=[{"do": "add", "object": "tag:2", "path": table, "value": row("event_id")}])
    items = operation(id="D2-OP02", actions=[{"do": "add", "object": "tag:2", "path": table, "value": row("items")}])
    assert operations.simulate(model, [event_id, items])["ok"]
    whole = operation(id="D4-OP09", actions=[{"do": "set", "object": "tag:2", "path": table, "value": []}])
    assert any("both write" in e for e in operations.simulate(model, [event_id, whole])["errors"])
    same_row = operation(id="D1-OP09", actions=[
        {"do": "set", "object": "tag:2", "path": table + ".row:parameter=event_id.map:parameterValue.value", "value": "y"}])
    assert any("both write" in e for e in operations.simulate(model, [event_id, same_row])["errors"])
    assert operations.simulate(model, [event_id, {**same_row, "depends_on": ["D2-OP01"]}])["ok"]

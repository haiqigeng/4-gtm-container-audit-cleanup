"""Source model, rule catalog, packs, views and masking."""

import json

import pytest
from conftest import EMAIL, SECRET, ce_trigger, container, operation, p

from gtmaudit import operations, packs, rules, source


def test_model_graph(model):
    assert "tag:1" in model.objects and "variable:22" in model.objects
    assert ("tag:5", "Does Not Exist", "variable") in model.unresolved
    assert "variable:20" in model.reachable and "variable:22" not in model.reachable
    assert source.trigger_events(model, "10") == {"purchase"}


def test_rejects_server_and_duplicates(tmp_path):
    data = container()
    data["containerVersion"]["client"] = [{"clientId": "1"}]
    path = tmp_path / "server.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(source.SourceError):
        source.load(path)
    data = container()
    data["containerVersion"]["tag"].append(dict(data["containerVersion"]["tag"][0]))
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(source.SourceError):
        source.load(path)


def test_rules_fire_on_seeded_cases(model):
    fired = {c.rule for c in rules.run(model).candidates}
    for rule in ("C04", "C10", "G06", "G13", "G10", "X13", "P01", "H04", "D03", "F04", "R01", "C03"):
        assert rule in fired, rule


def test_rule_registry_is_consistent():
    reg = rules.registry()
    assert all(spec[0] in rules.DOMAINS for spec in reg.values())
    assert len(reg) >= 90


def test_packs_mask_private_values(model, tmp_path):
    result = rules.run(model)
    written = packs.write_packs(model, result, {}, tmp_path)
    text = "".join((tmp_path / "packs" / name).read_text(encoding="utf-8") for names in written.values()
                   for name in names)
    assert SECRET not in text and EMAIL not in text
    assert "D5-blind.md" in written["D5-blind"]
    assert all((tmp_path / "packs" / n).stat().st_size <= packs.PAGE_LIMIT + 20_000
               for names in written.values() for n in names)


def test_references_include_folders_and_templates(model):
    delete_folder = operation(id="D4-OP06", actions=[{"do": "delete", "object": "folder:30"}])
    assert any("missing folder" in e for e in operations.simulate(model, [delete_folder])["errors"])
    unknown_template = operation(id="D3-OP01", actions=[{"do": "create", "layer": "tag", "ref": "new:tag:x", "object": {
        "name": "Vendor x", "type": "cvt_1_99", "firingTriggerId": ["10"]}}])
    assert any("missing template" in e for e in operations.simulate(model, [unknown_template])["errors"])


def test_plan_rendering_masks_and_reads_formats(tmp_path):
    csv_plan = tmp_path / "plan.csv"
    csv_plan.write_text(f"event;parameter;owner\npurchase;transaction_id;{EMAIL}\n", encoding="utf-8")
    text = packs.render_plan(csv_plan)
    assert "purchase | transaction_id" in text and EMAIL not in text
    from openpyxl import Workbook
    wb = Workbook()
    wb.active.append(["Événement", "Paramètre"])
    wb.active.append(["add_to_cart", "items"])
    xlsx = tmp_path / "plan.xlsx"
    wb.save(xlsx)
    assert "add_to_cart | items" in packs.render_plan(xlsx)


def test_template_views_show_code_and_permissions(model):
    from gtmaudit import render
    text = render.render(model, model.get("template:40"))
    assert "sandboxed code (" in text and "injectScript(" in text
    assert "permissions: inject_script" in text
    assert ("template:40", "template") in model.dependencies("tag:6")


def test_user_data_candidate_states_a_fact_not_a_contract():
    from gtmaudit.rules import consent_privacy
    assert "accepts" not in consent_privacy.RULES["A07"][3] and "pre-hashed" not in consent_privacy.RULES["A07"][3]


def test_consent_event_name_is_a_hint_not_a_predicate(tmp_path):
    from gtmaudit import source
    data = container()
    cv = data["containerVersion"]
    cv["trigger"].append(ce_trigger("15", "CE - didomi-consent", "didomi-consent"))
    cv["tag"][3]["firingTriggerId"] = ["15"]
    cv["tag"][3]["blockingTriggerId"] = []
    path = tmp_path / "e.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    m = source.load(path)
    controls = source.consent_controls(m, m.get("tag:4"))
    assert not source.has_consent_control(controls) and controls["hints"] == ["15"]


def test_privacy_projection_keeps_field_names_and_masks_values(model):
    from gtmaudit import render
    from gtmaudit.privacy import mask_structure
    from gtmaudit.steps import Interface
    secret = "cs_9f8e7d6c5b4a3210zz"
    row = {"type": "MAP", "map": [p("name", "consumer_secret"), p("value", secret)]}
    shown = " ".join(render.render_param(mask_structure({"type": "LIST", "key": "params", "list": [row]})))
    assert "consumer_secret" in shown and secret not in shown
    text = Interface(model, [], "en").step({"do": "add", "object": "tag:3", "path": "parameter:params.list", "value": row})
    assert "consumer_secret" in text and secret not in text
    assert SECRET not in render.render(model, model.get("tag:4"))


def test_value_sources_listed_once_per_variable_in_packs(model, tmp_path):
    from gtmaudit import render
    assert "{{DLV - value}} (variable:20): dataLayer 'ecommerce.value'" in render.render(model, model.get("tag:2"))
    result = rules.run(model)
    written = packs.write_packs(model, result, {}, tmp_path)
    d2 = "".join((tmp_path / "packs" / n).read_text(encoding="utf-8") for n in written["D2"])
    assert d2.count("{{DLV - value}} (variable:20): dataLayer") == 1 and "## Value sources" in d2


def test_effective_parameters_inherit_then_override(model):
    params = source.effective_parameters(model, model.get("tag:2"))
    assert params["debug_mode"] == "true" and params["value"] == "{{DLV - value}}"
    raw = container()
    raw["containerVersion"]["tag"][1]["parameter"][2]["list"].append(
        {"type": "MAP", "map": [p("parameter", "debug_mode"), p("parameterValue", "false")]})
    assert source.effective_parameters(source.from_raw(raw), source.from_raw(raw).get("tag:2"))["debug_mode"] == "false"

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

SECRET = "sk_live_9f8e7d6c5b4a3210"
EMAIL = "jane.doe@example.org"


def p(key, value, kind="TEMPLATE"):
    return {"type": kind, "key": key, "value": value}


def row(**entries):
    return {"type": "MAP", "map": [p(k, v) for k, v in entries.items()]}


def ce_trigger(tid, name, event):
    return {"triggerId": tid, "name": name, "type": "CUSTOM_EVENT",
            "customEventFilter": [{"type": "EQUALS", "parameter": [p("arg0", "{{_event}}"), p("arg1", event)]}]}


TEMPLATE_DATA = "\n".join([
    "___INFO___", "", '{"displayName": "Vendor template"}', "",
    "___WEB_PERMISSIONS___", "", '[{"instance": {"key": {"publicId": "inject_script"}}}]', "",
    "___SANDBOXED_JS_FOR_WEB_TEMPLATE___", "", "const injectScript = require('injectScript');",
    "injectScript('https://vendor.example/tag.js', data.gtmOnSuccess, data.gtmOnFailure);", ""])


def container():
    tags = [
        {"tagId": "1", "name": "GA4 - config", "type": "googtag", "firingTriggerId": ["2147479553"], "parentFolderId": "30",
         "parameter": [p("tagId", "G-ABCDEF1234"),
                       {"type": "LIST", "key": "configSettingsTable",
                        "list": [row(parameter="debug_mode", parameterValue="true"),
                                 row(parameter="send_page_view", parameterValue="true")]}]},
        {"tagId": "2", "name": "GA4 - purchase", "type": "gaawe", "firingTriggerId": ["10"], "blockingTriggerId": ["12"],
         "parameter": [p("eventName", "purchase"), p("measurementIdOverride", "G-ABCDEF1234"),
                       {"type": "LIST", "key": "eventSettingsTable",
                        "list": [row(parameter="value", parameterValue="{{DLV - value}}"),
                                 row(parameter="transaction_id", parameterValue="{{DLV - order}}")]}]},
        {"tagId": "3", "name": "Meta - base", "type": "html", "firingTriggerId": ["2147479553"],
         "parameter": [p("html", "<script>fbq('init','123456');fbq('track','PageView');</script>")]},
        {"tagId": "4", "name": "Vendor - cart", "type": "html", "firingTriggerId": ["11"], "blockingTriggerId": ["12"],
         "tagFiringOption": "ONCE_PER_LOAD",
         "parameter": [p("html", "<script>var api_key='" + SECRET + "';send('" + EMAIL + "');</script>")]},
        {"tagId": "6", "name": "Vendor - template tag", "type": "cvt_1_40", "firingTriggerId": ["11"],
         "blockingTriggerId": ["12"], "parameter": []},
        {"tagId": "5", "name": "Missing ref", "type": "html", "firingTriggerId": ["11"], "blockingTriggerId": ["12"],
         "parameter": [p("html", "<script>console.log({{Does Not Exist}})</script>")]},
    ]
    triggers = [
        ce_trigger("10", "CE - purchase", "purchase"),
        ce_trigger("11", "CE - add_to_cart", "add_to_cart"),
        {"triggerId": "12", "name": "Block - consent", "type": "CUSTOM_EVENT",
         "customEventFilter": [{"type": "MATCH_REGEX", "parameter": [p("arg0", "{{_event}}"), p("arg1", ".*")]}],
         "filter": [{"type": "CONTAINS", "parameter": [p("arg0", "{{Didomi vendors}}"), p("arg1", "iab:91")]}]},
        ce_trigger("13", "CE - purchase copy", "purchase"),
    ]
    variables = [
        {"variableId": "20", "name": "DLV - value", "type": "v", "parameter": [p("name", "ecommerce.value")]},
        {"variableId": "21", "name": "DLV - order", "type": "v", "parameter": [p("name", "ecommerce.transaction_id")]},
        {"variableId": "22", "name": "Unused constant", "type": "c", "parameter": [p("value", "x")]},
        {"variableId": "23", "name": "Didomi vendors", "type": "v", "parameter": [p("name", "didomiVendors")]},
    ]
    return {"exportFormatVersion": 2, "containerVersion": {
        "container": {"publicId": "GTM-TEST", "name": "test", "containerId": "1", "usageContext": ["WEB"]},
        "containerVersionId": "7", "tag": tags, "trigger": triggers, "variable": variables,
        "folder": [{"folderId": "30", "name": "Google"}],
        "customTemplate": [{"templateId": "40", "name": "Vendor template", "galleryReference": {"owner": "acme"},
                            "templateData": TEMPLATE_DATA}],
        "builtInVariable": [{"name": "Page URL", "type": "PAGE_URL"}]}}


@pytest.fixture
def export(tmp_path):
    path = tmp_path / "export.json"
    path.write_text(json.dumps(container()), encoding="utf-8")
    return path


@pytest.fixture
def model(export):
    from gtmaudit import source
    return source.load(export)


def finding(**overrides):
    base = {"type": "finding", "id": "D4-F01", "area": "A08", "title": "Cart tag capped", "class": "defect",
            "basis": "source", "severity": "High", "objects": ["tag:4"],
            "situation": "tag:4 fires once per page.",
            "impact": "Later add-to-carts are lost.", "recommendation": "Fire once per event.",
            "question": "Does the vendor expect one call per add-to-cart?", "readiness": "conditional",
            "operations": ["D4-OP01"], "candidates": []}
    base.update(overrides)
    return base


def operation(**overrides):
    base = {"type": "operation", "id": "D4-OP01", "title": "Fire per event", "findings": ["D4-F01"],
            "actions": [{"do": "set", "object": "tag:4", "path": "tagFiringOption", "value": "ONCE_PER_EVENT"}],
            "verification": "Preview twice.", "rollback": "Restore ONCE_PER_LOAD."}
    base.update(overrides)
    return base

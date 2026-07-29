from __future__ import annotations

from typing import Any


def multi_hundred_object_container(groups: int = 60) -> dict[str, Any]:
    """Return a deterministic, anonymized large web-container regression fixture."""

    folders = [
        {"folderId": str(index), "name": f"Measurement group {index}"}
        for index in range(1, 13)
    ]
    triggers = [
        {
            "triggerId": str(10_000 + index),
            "name": f"CE - business_event_{index}",
            "type": "CUSTOM_EVENT",
            "customEventFilter": [
                {
                    "type": "EQUALS",
                    "parameter": [
                        {"key": "arg0", "type": "TEMPLATE", "value": "{{_event}}"},
                        {
                            "key": "arg1",
                            "type": "TEMPLATE",
                            "value": f"business_event_{index}",
                        },
                    ],
                }
            ],
            "parentFolderId": str((index % len(folders)) + 1),
        }
        for index in range(1, groups + 1)
    ]
    variables = [
        {
            "variableId": str(20_000 + index),
            "name": f"DLV - eventModel.value_{index}",
            "type": "v",
            "parameter": [
                {
                    "key": "name",
                    "type": "TEMPLATE",
                    "value": f"eventModel.value_{index}",
                },
                {"key": "dataLayerVersion", "type": "INTEGER", "value": "2"},
            ],
            "parentFolderId": str((index % len(folders)) + 1),
        }
        for index in range(1, groups + 1)
    ]
    variables.extend(
        {
            "variableId": str(30_000 + index),
            "name": f"DLV - eventModel.id_{index}",
            "type": "v",
            "parameter": [
                {
                    "key": "name",
                    "type": "TEMPLATE",
                    "value": f"eventModel.id_{index}",
                },
                {"key": "dataLayerVersion", "type": "INTEGER", "value": "2"},
            ],
            "parentFolderId": str((index % len(folders)) + 1),
        }
        for index in range(1, groups + 1)
    )
    tags = []
    for index in range(1, groups + 1):
        trigger_id = str(10_000 + index)
        folder_id = str((index % len(folders)) + 1)
        destination = f"G-LARGE-{(index % 12) + 1:02d}"
        tags.extend(
            [
                {
                    "tagId": str(40_000 + index),
                    "name": f"GA4 - business_event_{index}",
                    "type": "gaawe",
                    "parameter": [
                        {
                            "key": "eventName",
                            "type": "TEMPLATE",
                            "value": f"business_event_{index}",
                        },
                        {
                            "key": "measurementId",
                            "type": "TEMPLATE",
                            "value": destination,
                        },
                        {
                            "key": "eventParameters",
                            "type": "LIST",
                            "list": [
                                {
                                    "key": "value",
                                    "type": "TEMPLATE",
                                    "value": f"{{{{DLV - eventModel.value_{index}}}}}",
                                },
                                {
                                    "key": "item_id",
                                    "type": "TEMPLATE",
                                    "value": f"{{{{DLV - eventModel.id_{index}}}}}",
                                },
                            ],
                        },
                    ],
                    "firingTriggerId": [trigger_id],
                    "parentFolderId": folder_id,
                },
                {
                    "tagId": str(50_000 + index),
                    "name": f"Media - business_event_{index}",
                    "type": "html",
                    "parameter": [
                        {
                            "key": "html",
                            "type": "TEMPLATE",
                            "value": (
                                "<script>window.mediaQueue=window.mediaQueue||[];"
                                f"window.mediaQueue.push({{event:'business_event_{index}',"
                                f"id:'{{{{DLV - eventModel.id_{index}}}}}'}});</script>"
                            ),
                        }
                    ],
                    "firingTriggerId": [trigger_id],
                    "parentFolderId": folder_id,
                },
            ]
        )
    return {
        "exportFormatVersion": 2,
        "containerVersion": {
            "accountId": "100",
            "containerId": "200",
            "containerVersionId": "1",
            "container": {"publicId": "TST-LARGE", "usageContext": ["WEB"]},
            "tag": tags,
            "trigger": triggers,
            "variable": variables,
            "folder": folders,
            "builtInVariable": [{"name": "Event"}],
        },
    }

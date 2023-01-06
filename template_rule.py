import typing
import json

from panther_sdk import detection, PantherEvent
from panther_utils import match_filters

from .panther_gsuite._shared import (
    pick_filters
)


def rule_filter() -> detection.PythonFilter:
    def _rule_filter(event: PantherEvent) -> bool:
        return False
    
    return detection.PythonFilter(func=_rule_filter)


def rule(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    ) -> detection.Rule:

    def _title(event: PantherEvent, example: str) -> str:
        return f"{example}"
    
    def _make_context(event):
        return event

    def _reference_generator():
        return "A URL to an explanation of this type of detection or attack"

    def _alert_grouping(event: PantherEvent) -> str:
        return "Dedup string"
    
    

    return detection.Rule(
        rule_id=(overrides.rule_id or "LogFamily.LogType.DetectionName"),
        name=(overrides.name or "Human Readable Detection Name"),
        log_types=(overrides.log_types or ["LogType.Name"]),
        tags=(overrides.tags or ["Tag"]),
        severity=(overrides.severity or detection.SeverityInfo),
        description=(
            overrides.description
            or "A description of the detection's impact and why it exists"
        ),
        reference=(
            overrides.reference
            or _reference_generator
        ),
        runbook=(
            overrides.runbook
            or "Follow up with user to remove this forwarding rule if not allowed."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_not_exists("a condition I want to filter out"),
                rule_filter()
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        alert_context=(overrides.alert_context or _make_context),
        summary_attrs=(overrides.summary_attrs or ["fieldName", "fieldName:nestedFieldName"]),
        unit_tests=(
            overrides.unit_tests
            or [
                    detection.JSONUnitTest(
                    name="Name",
                    expect_match=False,
                    data=json.dumps({
                        "JSON": "string"
                        },
                )),
            ]
        ),
        alert_grouping=(overrides.alert_grouping or _alert_grouping)
    )


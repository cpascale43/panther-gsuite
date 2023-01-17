import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_passthrough_rule(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite Passthrough Rule Triggered"""

    def _title(event: PantherEvent) -> str:
        rule_severity = event.deep_get(event, "parameters", "severity")

        if event.deep_get(event, "parameters", "rule_name"):
            return (
                "GSuite "
                + rule_severity
                + " Severity Rule Triggered: "
                + event.deep_get(event, "parameters", "rule_name")
            )

        return "GSuite " + rule_severity + " Severity Rule Triggered"



    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.Rule"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT ## Check this
        ),
        severity=(overrides.severity or detection.SeverityInfo),
        description=(
            overrides.description
            or "A GSuite rule was triggered."
        ),
        reference=(
            overrides.reference
            or "https://support.google.com/a/answer/9420866"
        ),
        runbook=(
            overrides.runbook or "Investigate what triggered the rule."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            #name == change_calendars_acls &
            #parameters.grantee_email == __public_principal__@public.calendar.google.com
            defaults=[
                match_filters.deep_equal("id.applicationName", "rules"),
                match_filters.deep_exists("parameters.triggered_actions")
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="High Severity Rule",
                    expect_match=True,
                    data=sample_logs.high_severity_rule,
                ),
                detection.JSONUnitTest(
                    name="High Severity Rule with Rule Name",
                    expect_match=True,
                    data=sample_logs.high_severity_rule_with_rule_name,
                ),
                detection.JSONUnitTest(
                    name="Medium Severity Rule",
                    expect_match=True,
                    data=sample_logs.medium_severity_rule,
                ),
                    detection.JSONUnitTest(
                    name="Low Severity Rule",
                    expect_match=True,
                    data=sample_logs.low_severity_rule,
                ),
                detection.JSONUnitTest(
                    name="Non Triggered Rule",
                    expect_match=False,
                    data=sample_logs.non_triggered_rule,
                )
            ]
        ),
    )
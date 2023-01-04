import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_device_suspicious_activity(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a suspicious activity on a user's device."""

    def _title(event: PantherEvent) -> str:
        return (     
            f"User [{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
            f"'s device was compromised"
        )


    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.DeviceSuspiciousActivity"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT ## Check this
        ),
        severity=(overrides.severity or detection.SeverityLow),
        description=(
            overrides.description
            or "GSuite reported a suspicious activity on a user's device."
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#SUSPICIOUS_ACTIVITY_EVENT"
        ),
        runbook=(
            overrides.runbook or "Validate that the suspicious activity was expected by the user."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_equal("id.applicationName", "mobile"),
                match_filters.deep_equal("name", "SUSPICIOUS_ACTIVITY_EVENT"),

            ],
        ),
        alert_title=(overrides.alert_title or _title),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Suspicious Activity",
                    expect_match=True,
                    data=sample_logs.suspicious_activity,
                ),
                detection.JSONUnitTest(
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=sample_logs.normal_mobile_event,
                )
            ]
        ),
    )
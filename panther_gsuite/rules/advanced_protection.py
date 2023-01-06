import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_advanced_protection(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user disabled advanced protection for themselves."""

    def _title(event: PantherEvent) -> str:
        return (  
            f"Advanced protection was disabled for user "   
            f"[{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
        )


    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.AdvancedProtection"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT ## Check this
        ),
        severity=(overrides.severity or detection.SeverityLow),
        description=(
            overrides.description
            or "A user disabled advanced protection for themselves."
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts#titanium_change"
        ),
        runbook=(
            overrides.runbook or "Have the user re-enable Google Advanced Protection"
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,

            defaults=[
                match_filters.deep_equal("id.applicationName", "user_accounts"),
                match_filters.deep_equal("name", "titanium_unenroll"),
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Advanced Protection Disabled",
                    expect_match=True,
                    data=sample_logs.advanced_protection_disabled,
                ),
                detection.JSONUnitTest(
                    name="Advanced Protection Enabled",
                    expect_match=False,
                    data=sample_logs.advanced_protection_enabled,
                )
            ]
        ),
    )
import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_brute_force_login(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was denied login access several times"""

    def _title(event: PantherEvent) -> str:
        return f"Brute force login suspected for user [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}"

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.BruteForceLogin"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT
        ),
        reports=(overrides.reports or {
                 detection.ReportKeyMITRE: ["TA0005:T1556"]}),
        severity=(overrides.severity or detection.SeverityHigh),
        description=(
            overrides.description
            or "A GSuite user was denied login access several times"
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#login_failure"
        ),
        runbook=(
            overrides.runbook or "Analyze the IP they came from and actions taken before/after"
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_equal(
                    "name", "login_failure"),
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="login_failure",
                    expect_match=True,
                    data=sample_logs.login_failure,
                )
            ]
        ),
    )
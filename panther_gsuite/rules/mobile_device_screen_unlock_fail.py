import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_mobile_device_screen_unlock_fail(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite User Device Unlock Failures"""
        
    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
            f"'s device had multiple failed unlock attempts"
        )
    
                
    return detection.Rule(
        name=(overrides.name or "GSuite User Device Unlock Failures"),
        rule_id=(overrides.rule_id or "GSuite.DeviceUnlockFailure"),
        log_types=(overrides.log_types or ['GSuite.ActivityEvent']),
        tags=(
            overrides.tags
            or  ['GSuite', 'Credential Access:Brute Force'],
        ),
        reports=(overrides.reports or {'MITRE ATT&CK': ['TA0006:T1110']}),
        severity=(overrides.severity or detection.SeverityMedium),
        description=(
            overrides.description 
            or "Someone failed to unlock a user's device multiple times in quick succession."
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#FAILED_PASSWORD_ATTEMPTS_EVENT"
        ),
        runbook=(
            overrides.runbook
            or "Verify that these unlock attempts came from the user, and not a malicious actor which has acquired the user's device."
        ),
        threshold=(overrides.threshold),
        alert_title=(overrides.alert_title or _title),
        summary_attrs=(
            overrides.summary_attrs
            or ['actor:email']
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_equal("id.applicationName", "mobile"),
                match_filters.deep_equal("name", "FAILED_PASSWORD_ATTEMPTS_EVENT"),
                match_filters.deep_greater_than(float("parameters.FAILED_PASSWD_ATTEMPTS"), 10)
            ],
        ),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=sample_logs.normal_mobile_event
                ),
                detection.JSONUnitTest(
                    name="Small Number of Failed Logins",
                    expect_match=False,
                    data=sample_logs.small_number_of_failed_logins
                ),
                detection.JSONUnitTest(
                    name="Multiple Failed Login Attempts with int Type",
                    expect_match=True,
                    data=sample_logs.multiple_failed_login_attempts_with_int_type
                ),
                detection.JSONUnitTest(
                    name="Multiple Failed Login Attempts with String Type",
                    expect_match=True,
                    data=sample_logs.multiple_failed_login_attempts_with_string_type
                ),
                
            ]
        )
    )
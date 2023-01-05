import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_leaked_password(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite User Password Leaked"""

    def _title(event: PantherEvent) -> str:
        user = event.deep_get("parameters", "affected_email_address")
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{user}]'s account was disabled due to a password leak" 
                    
    return detection.Rule(
        name=(overrides.name or "GSuite User Password Leaked"),
        rule_id=(overrides.rule_id or "GSuite.LeakedPassword"),
        log_types=(overrides.log_types or ['GSuite.ActivityEvent']),
        tags=(
            overrides.tags
            or ['GSuite', 'Credential Access:Unsecured Credentials'],
        ),
        reports=(overrides.reports or {'MITRE ATT&CK': ['TA0006:T1552']}),
        severity=(overrides.severity or detection.SeverityHigh),
        description=(
            overrides.description 
            or "GSuite reported a user's password has been compromised, so they disabled the account."
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#account_disabled_password_leak"
        ),
        runbook=(
            overrides.runbook
            or "GSuite has already disabled the compromised user's account. Consider investigating how the user's account was compromised, and reset their account and password. Advise the user to change any other passwords in use that are the sae as the compromised password."
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
                match_filters.deep_equal("id.applicationName", "login"),
                match_filters.deep_equal("type", "account_warning"),
                match_filters.deep_in("name", ["account_disabled_password_leak"])
            ],
        ),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Normal Login Event",
                    expect_match=False,
                    data=sample_logs.normal_login_event
                ),
                detection.JSONUnitTest(
                    name="Account Warning Not For Password Leaked",
                    expect_match=False,
                    data=sample_logs.account_warning_not_for_password_leaked
                ),
                detection.JSONUnitTest(
                    name="Account Warning For Password Leaked",
                    expect_match=True,
                    data=sample_logs.account_warning_for_password_leaked
                ),
                
            ]
        )
    )
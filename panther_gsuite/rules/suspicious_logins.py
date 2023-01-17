import typing
import json

from panther_sdk import detection, PantherEvent
from panther_utils import match_filters

from .._shared import (
    pick_filters
)


def gsuite_suspicious_logins(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    ) -> detection.Rule:

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            SUSPICIOUS_LOGIN_TYPES = {
            "suspicious_login",
            "suspicious_login_less_secure_app",
            "suspicious_programmatic_login",
            }

            # now a filter :)
            # if event["id"]["applicationName"] != "login":
            #     return False
            
            return bool(event.get("name") in SUSPICIOUS_LOGIN_TYPES)
        
        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        user = event["parameters"]["affected_email_address"]
        if not user:
            user = "<UNKNOWN_USER>"
        return f"A suspicious login was reported for user [{user}]"
    
    def _make_context(event):
        return event

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.SuspiciousLogins"),
        name=(overrides.name or "Suspicious GSuite Login"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(overrides.tags or ["GSuite"]),
        severity=(overrides.severity or detection.SeverityMedium),
        description=(
            overrides.description
            or "GSuite reported a suspicious login for this user."
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#suspicious_login"
        ),
        runbook=(
            overrides.runbook
            or "Check out the details of the login and verify this behavior with the user to ensure the account wasn't compromised."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_equal("id.applicationName", "login"),
                rule_filter()
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        alert_context=(overrides.alert_context or _make_context),
        summary_attrs=(overrides.summary_attrs or ["actor:email"]),
        unit_tests=(
            overrides.unit_tests
            or [
                    detection.JSONUnitTest(
                    name="Normal Login Event",
                    expect_match=False,
                        data=json.dumps({
                        "id": {
                        "applicationName": "login",
                        },
                        "kind": "admin#reports#activity",
                        "type": "account_warning",
                        "name": "login_success",
                        "parameters": {
                        "affected_email_address": "bobert@ext.runpanther.io"
                        },
                        },
                    )),
                    detection.JSONUnitTest(
                    name="Account Warning For Suspicious Login",
                    expect_match=True,
                        data=json.dumps({
                        "id": {
                        "applicationName": "login",
                        },
                        "kind": "admin#reports#activity",
                        "type": "account_warning",
                        "name": "suspicious_login",
                        "parameters": {
                        "affected_email_address": "bobert@ext.runpanther.io"
                        },
                        },
                    )),
                ]
        ),
    )


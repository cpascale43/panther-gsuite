import typing
import json

from panther_sdk import detection, PantherEvent
from panther_utils import match_filters

from .._shared import (
    pick_filters
)


def gsuite_user_suspended(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    ) -> detection.Rule:

    def rule_filter() -> detection.PythonFilter:
        def _rule(event: PantherEvent) -> bool:
            USER_SUSPENDED_EVENTS = {
                "account_disabled_generic",
                "account_disabled_spamming_through_relay",
                "account_disabled_spamming",
                "account_disabled_hijacked",
            }

            # this is a filter now
            # if deep_get(event, "id", "applicationName") != "login":
            #     return False

            return bool(event.get("name") in USER_SUSPENDED_EVENTS)
    
        return detection.PythonFilter(func=_rule)

    def _title(event: PantherEvent) -> str:
        user = event["parameters"]["affected_email_address"]
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{user}]'s account was disabled"
    
    def _make_context(event: PantherEvent) -> dict:
        return event

    def _reference_generator() -> str:
        return "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#account_disabled_generic"

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.UserSuspended"),
        name=(overrides.name or "GSuite User Suspended"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(overrides.tags or ["GSuite"]),
        severity=(overrides.severity or detection.SeverityHigh),
        description=(
            overrides.description
            or "A GSuite user was suspended, the account may have been compromised by a spam network."
        ),
        reference=(
            overrides.reference
            or _reference_generator
        ),
        runbook=(
            overrides.runbook
            or "Investigate the behavior that got the account suspended. Verify with the user that this intended behavior. If not, the account may have been compromised."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                # the path needs to use dot notation as seen in this unit test: https://github.com/panther-labs/panther-utils/blob/main/tests/test_match_filters.py#L22 
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
                    name="Account Warning For Suspended User",
                    expect_match=True,
                    data=json.dumps({
                        "id": {
                                "applicationName": "login",
                        },
                        "kind": "admin#reports#activity",
                        "type": "account_warning",
                        "name": "account_disabled_spamming",
                        "parameters": {
                            "affected_email_address": "bobert@ext.runpanther.io"
                        },
                    },
                )),
                detection.JSONUnitTest(
                    name="Account Warning Not For Suspended User",
                    expect_match=False,
                    data=json.dumps({
                        "id": {
                            "applicationName": "login",
                        },
                        "kind": "admin#reports#activity",
                        "type": "account_warning",
                        "name": "suspicious_login ",
                        "parameters": {
                            "affected_email_address": "bobert@ext.runpanther.io"
                        },
                    },
                )),
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
                    name="Not a Login Event",
                    expect_match=False,
                    data=json.dumps({
                        "id": {
                            "applicationName": "something other than a login",
                        } 
                    },
                )),
            ]
        )
    )
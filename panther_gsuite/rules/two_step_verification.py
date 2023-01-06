import typing
import json

from panther_sdk import detection, PantherEvent
from panther_utils import match_filters

from .._shared import (
    pick_filters
)


def gsuite_two_step_verification(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    ) -> detection.Rule:

    def rule_filter() -> detection.PythonFilter:
        def _rule(event: PantherEvent) -> bool:
            if event.get("type") == "2sv_change" and event.get("name") == "2sv_disable":
                return True
            return False
    
        return detection.PythonFilter(func=_rule)

    def _title(event: PantherEvent) -> str:
        from ..global_helpers import deep_get
        return (
        f"Two step verification was disabled for user"
        f" [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
    )
    
    def _make_context(event: PantherEvent) -> dict:
        return event

    def _reference_generator() -> str:
        return "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts"

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.TwoStepVerification"),
        name=(overrides.name or "GSuite User Two Step Verification Change"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(overrides.tags or ["GSuite", "Defense Evasion:Modify Authentication Process"]),
        severity=(overrides.severity or detection.SeverityLow),
        description=(
            overrides.description
            or "A user disabled two step verification for themselves."
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
                match_filters.deep_equal("id.applicationName", "user_accounts"),
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
                    name="Two Step Verification Disabled",
                    expect_match=True,
                    data=json.dumps({
                        "id": {
                        "applicationName": "user_accounts",
                        },
                        "actor": {
                        "callerType": "USER",
                        "email": "some.user@somedomain.com",
                        },
                        "kind": "admin#reports#activity",
                        "type": "2sv_change",
                        "name": "2sv_disable",
                    }
                )),
            ]
        )
    )
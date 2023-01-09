import typing
import json

from panther_sdk import detection, PantherEvent
from panther_utils import match_filters
# helpers need to be imported at the function level unfortunately
from ..global_helpers import deep_get

from panther_gsuite._shared import (
    pick_filters,
)


def gsuite_device_compromised(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            # from global_helpers import deep_get
            if event.get("name") == "DEVICE_COMPROMISED_EVENT":
                # return bool(deep_get(event, "parameters", "DEVICE_COMPROMISED_STATE") == "COMPROMISED")
                return bool(event["parameters"]["DEVICE_COMPROMISED_STATE"] == "COMPROMISED")

            return False

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        from global_helpers import deep_get
        return (
            f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] "
            f"banned another user from a group."
            # f"User [{event['actor']['email']}] "
            # f"banned another user from a group."
        )

    def _make_context(event):
        return event

    def _reference_generator() -> str:
        return "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#DEVICE_COMPROMISED_EVENT"

    # def _alert_grouping(event: PantherEvent) -> str:
    #     return "Dedup string"

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.DeviceCompromise"),
        name=(overrides.name or "GSuite User Device Compromised"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(overrides.tags or ["GSuite"]),
        severity=(overrides.severity or detection.SeverityMedium),
        description=(
            overrides.description
            or "GSuite reported a user's device has been compromised."
        ),
        reference=(
            overrides.reference
            or _reference_generator
        ),
        runbook=(
            overrides.runbook
            or "Have the user change their passwords and reset the device."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_equal(
                    "id.applicationName", "mobile"),
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
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=json.dumps({
                        "id": {
                            "applicationName": "mobile",
                        },
                        "actor": {
                            "callerType": "USER",
                            "email": "homer.simpson@example.io",
                        },
                        "type": "device_updates",
                        "name": "DEVICE_REGISTER_UNREGISTER_EVENT",
                        "parameters": {
                            "USER_EMAIL": "homer.simpson@example.io"
                        }
                    }
                    )),
                detection.JSONUnitTest(
                    name="Suspicious Activity Shows Compromised",
                    expect_match=True,
                    data=json.dumps({
                        "id": {
                            "applicationName": "mobile",
                        },
                        "actor": {
                            "callerType": "USER",
                            "email": "homer.simpson@example.io",
                        },
                        "type": "device_updates",
                        "name": "DEVICE_COMPROMISED_EVENT",
                        "parameters": {
                            "USER_EMAIL": "homer.simpson@example.io",
                            "DEVICE_COMPROMISED_STATE": "COMPROMISED"
                        }
                    }
                    )),
            ]
        ),
        # alert_grouping=(overrides.alert_grouping or _alert_grouping)
    )

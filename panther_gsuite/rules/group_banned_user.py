import typing
import json

from panther_sdk import detection, PantherEvent
from panther_utils import match_filters

from panther_gsuite._shared import (
    pick_filters,
)




def gsuite_group_banned_user(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            if event.get("type") == "moderator_action":
                return bool(event.get("name") == "ban_user_with_moderation")

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        from global_helpers import deep_get
        return (
            f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] "
            f"banned another user from a group."
        )

    def _make_context(event):
        return event

    def _reference_generator() -> str:
        return "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups-enterprise#ban_user_with_moderation"

    # def _alert_grouping(event: PantherEvent) -> str:
    #     return "Dedup string"

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.GroupBannedUser"),
        name=(overrides.name or "Human Readable Detection Name"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(overrides.tags or ["GSuite"]),
        severity=(overrides.severity or detection.SeverityLow),
        description=(
            overrides.description
            or "A GSuite user was banned from an enterprise group by moderator action."
        ),
        reference=(
            overrides.reference
            or _reference_generator
        ),
        runbook=(
            overrides.runbook
            or "Investigate the banned user to see if further disciplinary action needs to be taken."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_equal(
                    "id.applicationName", "groups_enterprise"),
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
                    name="User Added",
                    expect_match=False,
                    data=json.dumps({
                        "id": {
                            "applicationName": "groups_enterprise",
                        },
                        "actor": {
                            "email": "homer.simpson@example.com"
                        },
                        "type": "moderator_action",
                        "name": "add_member",
                    },
                    )),
                detection.JSONUnitTest(
                    name="User Banned from Group",
                    expect_match=True,
                    data=json.dumps({
                        "id": {
                            "applicationName": "groups_enterprise",
                        },
                        "actor": {
                            "email": "homer.simpson@example.com"
                        },
                        "type": "moderator_action",
                        "name": "ban_user_with_moderation",
                    },
                    )),
            ]
        ),
        # alert_grouping=(overrides.alert_grouping or _alert_grouping)
    )

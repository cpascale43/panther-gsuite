import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_gov_attack(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported that it detected a government backed attack against your account."""

    def _title(event: PantherEvent) -> str:
        return (     
            f"User [{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] may have been "
            f"targeted by a government attack"
        )


    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.GovernmentBackedAttack"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT ## Check this
        ),
        severity=(overrides.severity or detection.SeverityCritical),
        description=(
            overrides.description
            or "GSuite reported that it detected a government backed attack against your account."
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#gov_attack_warning"
        ),
        runbook=(
            overrides.runbook or "Follow up with GSuite support for more details."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            #name == change_calendars_acls &
            #parameters.grantee_email == __public_principal__@public.calendar.google.com
            defaults=[
                match_filters.deep_equal("name", "gov_attack_warning"),
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Gov backed warning",
                    expect_match=True,
                    data=sample_logs.gov_backed_warning,
                ),
                detection.JSONUnitTest(
                    name="Normal login",
                    expect_match=False,
                    data=sample_logs.normal_login,
                )
            ]
        ),
    )
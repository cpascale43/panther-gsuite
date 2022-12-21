import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_calendar_made_public(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite Calendar Has Been Made Public"""

    def _title(event: PantherEvent) -> str:
        return f"Gsuite calendar [{event.deep_get('parameters', 'calendar_id', default='<NO_CALENDAR_ID>')}] made public by [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
        # return f"Brute force login suspected for user [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}"

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.CalendarMadePublic"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT ## Check this
        ),
        reports=(overrides.reports or {
                 detection.ReportKeyMITRE: ["TA0007:T1087"]}),
        severity=(overrides.severity or detection.SeverityMedium),
        description=(
            overrides.description
            or "A User or Admin Has Modified A Calendar To Be Public"
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/calendar#change_calendar_acls"
        ),
        runbook=(
            overrides.runbook or "Follow up with user about this calendar share."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            #name == change_calendars_acls &
            #parameters.grantee_email == __public_principal__@public.calendar.google.com
            defaults=[
                match_filters.deep_equal(
                    "name", "change_calendar_acls"),
                match_filters.deep_equal(
                    "parameters.grantee_email", "__public_principal__@public.calendar.google.com")
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="User publicly shared calendar",
                    expect_match=True,
                    data=sample_logs.user_publicly_shared_calendar,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_WRITE_ACCESS",
                    expect_match=False,
                    data=sample_logs.admin_set_default_cal_setting,
                ),
                detection.JSONUnitTest(
                    name="List Object Type",
                    expect_match=False,
                    data=sample_logs.list_object_type,
                ),
            ]
        ),
    )
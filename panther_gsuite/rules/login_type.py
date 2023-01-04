import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)

def gsuite_login_type(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite Login Type"""

    # allow-list of approved login types
    APPROVED_LOGIN_TYPES = {
        "exchange",
        "google_password",
        "reauth",
        "saml",
        "unknown",
    }

    # allow-list any application names here
    APPROVED_APPLICATION_NAMES = {"saml"}

    def _title(event: PantherEvent) -> str:
        return (     
            f"A login attempt of a non-approved type was detected for user "
            f"[{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
        )


    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.LoginType"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT ## Check this
        ),
        severity=(overrides.severity or detection.SeverityMedium),
        description=(
            overrides.description
            or "A login of a non-approved type was detected for this user."
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#login"
        ),
        runbook=(
            overrides.runbook or "Correct the user account settings so that only logins of approved types are available."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            #name == change_calendars_acls &
            #parameters.grantee_email == __public_principal__@public.calendar.google.com
            defaults=[
                match_filters.deep_equal("type", "login"),
                match_filters.deep_not_equal("name", "logout"),
                match_filters.deep_not_in("parameters.login_type", APPROVED_LOGIN_TYPES),
                match_filters.deep_not_in("id.applicationName", APPROVED_APPLICATION_NAMES)
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Login With Unapproved Type",
                    expect_match=True,
                    data=sample_logs.login_with_unapproved_type,
                ),
                detection.JSONUnitTest(
                    name="Login With Approved Type",
                    expect_match=False,
                    data=sample_logs.login_with_approved_type,
                ),
                detection.JSONUnitTest(
                    name="Non-Login event",
                    expect_match=False,
                    data=sample_logs.non_login_event,
                ),
                detection.JSONUnitTest(
                    name="Saml Login Event",
                    expect_match=False,
                    data=sample_logs.saml_login_event,
                ),
                
            ]
        ),
    )
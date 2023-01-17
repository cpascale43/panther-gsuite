import typing

from panther_sdk import detection, PantherEvent
from panther_utils import match_filters

from .. import sample_logs
from .._shared import (
    pick_filters,
    create_alert_context
)

# where do I put the rule logic??????? - answer: I think all logic is a filter now and you can make a custom filter containing your rule function like this
def rule_filter() -> detection.PythonFilter:
    def _rule_filter(event: PantherEvent) -> bool:
        # is deep_get not available?
        ALLOWED_DOMAINS = ["example.com"]  # List of external domains that are allowed to be forwarded to

        # if event.deep_get("id", "applicationName") != "user_accounts":
        #     return False

        if event.get("name") == "email_forwarding_out_of_domain":
            # domain = event.deep_get("parameters", "email_forwarding_destination_address").split("@")[
            #     -1
            # ]
            domain = event["parameters"]["email_forwarding_destination_address"].split("@")[
                -1
            ]
            if domain not in ALLOWED_DOMAINS:
                return True
            return False
    
    return detection.PythonFilter(func=_rule_filter)


def gsuite_external_forwarding(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    ) -> detection.Rule:

    def _title(event: PantherEvent) -> str:
        # external_address = deep_get(event, "parameters", "email_forwarding_destination_address")
        # external_address = event.deep_get("parameters", "email_forwarding_destination_address")
        external_address = "yahoo.com"
        # user = deep_get(event, "actor", "email")
        # user = event.deep_get("actor", "email")
        user = "badactor@yahoo.com"
        return f"An email forwarding rule was created by {user} to {external_address}"

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.ExternalMailForwarding"),
        name=(overrides.name or "Gsuite Mail forwarded to external domain"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(overrides.tags or ["GSuite", "Collection:Email Collection"]),
        severity=(overrides.severity or detection.SeverityHigh),
        description=(
            overrides.description
            or "A user has configured mail forwarding to an external domain"
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#email_forwarding_out_of_domain"
        ),
        runbook=(
            overrides.runbook
            or "Follow up with user to remove this forwarding rule if not allowed."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_not_exists("user_accounts"),
                rule_filter()
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        alert_context=(overrides.alert_context or create_alert_context),
        summary_attrs=(overrides.summary_attrs or ["p_any_emails"]),
        unit_tests=(
            overrides.unit_tests
            or [
                    detection.JSONUnitTest(
                    name="Forwarding to External Address",
                    expect_match=True,
                    data=sample_logs.forwarding_to_external_address,
                ),
            ]
        ),
    )
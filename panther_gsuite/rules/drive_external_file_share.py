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
    """External GSuite File Share"""

    def _title(event: PantherEvent) -> str:
        return (     
            f"User [{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] may have been "
            f"targeted by a government attack"
        )


    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.Drive.ExternalFileShare"),
        log_types=(overrides.log_types or ["GSuite.Reports"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT ## Check this
        ),
        severity=(overrides.severity or detection.SeverityHigh),
        description=(
            overrides.description
            or "An employee shared a sensitive file externally with another organization"
        ),
        reference=(
            overrides.reference
            or ""
        ),
        runbook=(
            overrides.runbook or "Contact the employee who made the share and make sure they redact the access. If the share was legitimate, add to the EXCEPTION_PATTERNS in the detection."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_equal("id.applicationName", "drive"),
                ##Confused

            ],
        ),
        alert_title=(overrides.alert_title or _title),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Dangerous Share of Known Document with a Missing User",
                    expect_match=True,
                    data=sample_logs.dangerous_share_of_known_doc_with_a_missing_user
                ),
                detection.JSONUnitTest(
                    name="Dangerous Share of Unknown Document",
                    expect_match=True,
                    data=sample_logs.dangerous_share_of_unknown_doc,
                ),
                detection.JSONUnitTest(
                    name="Share Allowed by Exception",
                    expect_match=False,
                    data=sample_logs.share_allowed_by_exception,
                )
            ]
        ),
    )
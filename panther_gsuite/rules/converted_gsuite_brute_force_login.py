import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters,
    create_alert_context
)

# possible gotchas & FAQs:
# where can I see a list of function parameters? 
# how do I know which parameters are required?
# what does detection.JSONUnitTest do? (over a JSON dict)
# can I still use panther_analysis_tool? can't find documentation on `panther_analysis_tool sdk` 
# why am I seeing [ERROR]: Did not find a Panther SDK based module at ./panther_content when I try to run pat sdk test?

'''
[8:35:52] √ ~/Desktop/panther-labs/panther-gsuite/panther_gsuite/rules (main) % pat sdk test converted_gsuite_brute_force_login.py
usage: panther_analysis_tool [-h] [--version] [--debug] {release,test,publish,upload,delete,update-custom-schemas,test-lookup-table,zip,check-connection,sdk} ...
panther_analysis_tool: error: unrecognized arguments: converted_gsuite_brute_force_login.py
[8:36:00] ?2 ~/Desktop/panther-labs/panther-gsuite/panther_gsuite/rules (main) % pat sdk test 
[ERROR]: Did not find a Panther SDK based module at ./panther_content
'''

def gsuite_brute_force_login(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOptions = detection.RuleOptions(),
) -> detection.Rule:
    """A GSuite user was denied login access several times"""

    def _title(event: PantherEvent) -> str:
        return f"Brute force login suspected for user [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}"

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.BruteForceLogin"),
        log_types=(overrides.log_types or ["GSuite.ActivityEvent"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT
        ),
        reports=(overrides.reports or {
                 detection.ReportKeyMITRE: ["TA0005:T1556"]}),
        severity=(overrides.severity or detection.SeverityHigh),
        description=(
            overrides.description
            or "A GSuite user was denied login access several times"
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#login_failure"
        ),
        runbook=(
            overrides.runbook or "Analyze the IP they came from and actions taken before/after."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            defaults=[
                match_filters.deep_equal(
                    "eventName", "login_failure"),
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        alert_context=(overrides.alert_context or create_alert_context),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="login_failure",
                    expect_match=True,
                    data=sample_logs.login_failure,
                )
            ]
        ),
    )


def _rule(event: PantherEvent) -> bool:
    if event.get("type") != "login":
        return False
    return bool(event.get("name") == "login_failure")

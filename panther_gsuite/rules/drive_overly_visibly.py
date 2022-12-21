import typing
from panther_sdk import detection, PantherEvent
from panther_utils import standard_tags, match_filters

from .. import sample_logs
from .._shared import (
    pick_filters
)





### Global Helpers Begin ###
GSUITE_PARAMETER_VALUES = [
    "value",
    "intValue",
    "boolValue",
    "multiValue",
    "multiIntValue",
    "messageValue",
    "multiMessageValue",
]

def details_lookup(detail_type, detail_names, event):
    print(event())

    for details in event.deep_get("events"):
        print(details)
        if details.get("type") == detail_type and details.get("name") in detail_names:
            return details
    # not found, return empty dict
    return {}

def parameter_lookup(parameters, key):
    for param in parameters:
        if param["name"] != key:
            continue
        for value in GSUITE_PARAMETER_VALUES:
            if value in param:
                return param[value]
        return None
    return None

    
### Global helper ends ###    


### Rule Logic Begins ###
RESOURCE_CHANGE_EVENTS = {
    "create",
    "move",
    "upload",
    "edit",
}

PERMISSIVE_VISIBILITY = [
    "people_with_link",
    "public_on_the_web",
]

details = details_lookup("access", RESOURCE_CHANGE_EVENTS, PantherEvent)
doc_title = parameter_lookup(details.get("parameters", {}), "doc_title")
share_settings = parameter_lookup(details.get("parameters", {}), "visibility")
print(details)




def gsuite_drive_overly_visible(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite Calendar Has Been Made Public"""

    def _title(event: PantherEvent) -> str:
        #doc_title = parameter_lookup(details.get("parameters", {}), "doc_title")
        #share_settings = parameter_lookup(details.get("parameters", {}), "visibility")
        return (
            f"User [{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
            f" modified a document [{doc_title}] that has overly permissive share"
            f" settings [{share_settings}]"
        )  


    def _alert_grouping(event: PantherEvent) -> str:
        #details = details_lookup("access", RESOURCE_CHANGE_EVENTS, event)
        if parameter_lookup(details.get("parameters", {}), "doc_title"):
            return parameter_lookup(details.get("parameters", {}), "doc_title")
        return "<UNKNOWN_DOC_TITLE>"

    

    return detection.Rule(
        rule_id=(overrides.rule_id or "GSuite.DriveOverlyVisible"),
        log_types=(overrides.log_types or ["GSuite.Reports"]),
        tags=(
            overrides.tags or standard_tags.IDENTITY_AND_ACCESS_MGMT ## Check this
        ),
        reports=(overrides.reports or {
                 detection.ReportKeyMITRE: ["TA0009:T1213"]}),
        severity=(overrides.severity or detection.SeverityInfo),
        description=(
            overrides.description
            or "A Google drive resource that is overly visible has been modified."
        ),
        reference=(
            overrides.reference
            or "https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive#access"
        ),
        runbook=(
            overrides.runbook or "Investigate whether the drive document is appropriate to be this visible."
        ),
        filters=pick_filters(
            overrides=overrides,
            pre_filters=pre_filters,
            #name == change_calendars_acls &
            #parameters.grantee_email == __public_principal__@public.calendar.google.com
            defaults=[
                match_filters.deep_exists(
                    details
                ),
                match_filters.deep_in(
                    parameter_lookup(details.get("parameters", {}), PERMISSIVE_VISIBILITY)
                )
            ],
        ),
        alert_title=(overrides.alert_title or _title),
        alert_grouping=(overrides.alert_grouping or _alert_grouping),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Access Event",
                    expect_match=False,
                    data=sample_logs.access_event,
                ),
                detection.JSONUnitTest(
                    name="Modify Event Without Over Visibility",
                    expect_match=False,
                    data=sample_logs.modify_event_without_over_visibility,
                ),
                detection.JSONUnitTest(
                    name="Overly Visible Doc Modified",
                    expect_match=True,
                    data=sample_logs.overly_visible_doc_modified,
                ),
            ]
        ),
    )
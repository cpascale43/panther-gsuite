from typing import List, Optional, Dict, Any
from panther_sdk import detection, PantherEvent

# code used across different rules of the same log type go here

def create_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns common context for GSuite alerts"""

    return {
        "ips": event.get("p_any_ip_addresses", []),
        "emails": event.get("p_any_emails", "")
    }






# # # # # # # # # # # # # #
#      GSuite Helpers     #
# # # # # # # # # # # # # #

GSUITE_PARAMETER_VALUES = [
    "value",
    "intValue",
    "boolValue",
    "multiValue",
    "multiIntValue",
    "messageValue",
    "multiMessageValue",
]


# GSuite parameters are formatted as a list of dictionaries, where each dictionary has a 'name' key
# that maps to the name of the parameter, and one key from GSUITE_PARAMETER_VALUES that maps to the
# value of the parameter. This means to lookup the value of a particular parameter, you must
# traverse the entire list of parameters to find it and then know (or guess) what type of value it
# contains. This helper function handles that for us.
#
# Example parameters list:
# parameters = [
#   {
#       "name": "event_id",
#       "value": "abc123"
#   },
#   {
#       "name": "start_time",
#       "intValue": 63731901000
#   },
#   {
#       "name": "end_time",
#       "intValue": 63731903000
#   },
#   {
#       "name": "things",
#       "multiValue": [ "DRIVE" , "MEME"]
#   }
# ]
def gsuite_parameter_lookup(parameters, key):
    for param in parameters:
        if param["name"] != key:
            continue
        for value in GSUITE_PARAMETER_VALUES:
            if value in param:
                return param[value]
        return None
    return None


# GSuite event details are formatted as a list of dictionaries. Each entry has a 'type' and 'name'.
#
# In order to find the event details of interest, you must loop through
# the list searching for a particular type and name.
#
# This helper function handles the looping functionality that is common in many of the gsuite rules
def gsuite_details_lookup(detail_type, detail_names, event):
    for details in event.get("events", {}):
        if details.get("type") == detail_type and details.get("name") in detail_names:
            return details
    # not found, return empty dict
    return {}




def pick_filters(
    pre_filters: Optional[List[detection.AnyFilter]],
    overrides: detection.RuleOverrides,
    defaults: List[detection.AnyFilter],
) -> List[detection.AnyFilter]:
    if pre_filters is None:
        pre_filters = []

    if overrides.filters is None:
        return pre_filters + defaults
    else:
        if isinstance(overrides.filters, detection.AnyFilter):
            return pre_filters + [overrides.filters]

        if isinstance(overrides.filters, list):
            return pre_filters + overrides.filters

    raise RuntimeError("unable to pick filters")



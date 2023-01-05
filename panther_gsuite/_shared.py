from typing import List, Optional, Dict, Any
from panther_sdk import detection, PantherEvent

# code used across different rules of the same log type go here

def create_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns common context for GSuite alerts"""

    return {
        "ips": event.get("p_any_ip_addresses", []),
        "emails": event.get("p_any_emails", "")
    }

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



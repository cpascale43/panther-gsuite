from typing import List, Optional
from panther_config import PantherEvent
from panther_sdk import detection

def pick_filters(
    pre_filters: Optional[List[detection.AnyFilter]],
    overrides: detection.RuleOptions,
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

def create_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns common context for Okta alerts"""

    return {
        "ips": event.get("p_any_ip_addresses", []),
        "actor": event.get("actor", ""),
        "target": event.get("target", ""),
        "client": event.get("client", ""),
    }
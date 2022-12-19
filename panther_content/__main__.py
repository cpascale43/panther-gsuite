import panther_gsuite as gsuite
from panther_sdk import detection
from panther_utils import match_filters

gsuite.rules.brute_force_login(
    pre_filters=[
        match_filters.deep_not_equal("source_ip", "0.0.0.0"),
    ],
    overrides = detection.RuleOptions(
        # override the default "reference"
        reference="https://security-wiki.megacorp.internal/okta-incident-response",
		# override the default "severity" with INFO
		severity=detection.SeverityInfo
    )
)
import panther_gsuite.rules as gsuite_rules
from panther_sdk import detection
from panther_utils import match_filters
from . import customer_sample_logs
from panther_gsuite import sample_logs


gsuite_rules.gsuite_drive_overly_visible()

gsuite_rules.gsuite_brute_force_login(
    #only pass through if
    pre_filters=[
        match_filters.deep_not_equal_pattern(path="actor.email", pattern=".+@acme.com"),
    ],
    overrides = detection.RuleOverrides(
        # override the default "reference"
        reference="some custom gsuite reference",
		# override the default "severity" with INFO
		severity=detection.SeverityInfo,
        unit_tests=[
            detection.JSONUnitTest(
                name="My Test Override",
                expect_match=True,
                data=customer_sample_logs.my_custom_sample,
                ),
            detection.JSONUnitTest(
                name="My Domain Acme",
                expect_match=False,
                data=customer_sample_logs.acme_sample,
                )
        ]
    )
)

gsuite_rules.gsuite_calendar_made_public(
        # pre_filters=[
        #     match_filters.deep_equal("version", "0"),
        # ],

        # overrides = detection.RuleOverrides(
        #     # override the default "reference"
        #     reference="https://security-wiki.megacorp.internal/okta-incident-response",
		#     # override the default "severity" with INFO
		#     severity=detection.SeverityInfo
        # )
)
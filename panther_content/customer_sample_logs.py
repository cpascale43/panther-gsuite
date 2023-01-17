import json

my_custom_sample = json.dumps(
    {
        "id": {
            "applicationName": "login",
        },
        "actor": {
            "email": "some.user@somedomain.com",
        },
        "type": "login",
        "name": "login_failure",
    }
)

acme_sample = json.dumps(
    {
        "id": {
            "applicationName": "login",
        },
        "actor": {
            "email": "some.user@acme.com",
        },
        "type": "login",
        "name": "login_failure",
    }
)

import json

login_failure = json.dumps(
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

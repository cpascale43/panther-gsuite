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

user_publicly_shared_calendar = json.dumps(
      {
        "actor": {
          "email": "user@example.io",
          "profileId": "110111111111111111111"
        },
        "id": {
          "applicationName": "calendar",
          "customerId": "D12345",
          "time": "2022-12-10 22:33:31.852000000",
          "uniqueQualifier": "-2888888888888888888"
        },
        "ipAddress": "1.2.3.4",
        "kind": "admin#reports#activity",
        "name": "change_calendar_acls",
        "ownerDomain": "example.io",
        "parameters": {
          "access_level": "freebusy",
          "api_kind": "web",
          "calendar_id": "user@example.io",
          "grantee_email": "__public_principal__@public.calendar.google.com",
          "user_agent": "Mozilla/5.0"
        },
        "type": "calendar_change"
      }

)


admin_set_default_cal_setting = json.dumps(
      {
        "actor": {
          "callerType": "USER",
          "email": "example@example.io",
          "profileId": "12345"
        },
        "id": {
          "applicationName": "admin",
          "customerId": "D12345",
          "time": "2022-12-11 01:06:26.303000000",
          "uniqueQualifier": "-12345"
        },
        "ipAddress": "12.12.12.12",
        "kind": "admin#reports#activity",
        "name": "CHANGE_CALENDAR_SETTING",
        "parameters": {
          "DOMAIN_NAME": "example.io",
          "NEW_VALUE": "READ_WRITE_ACCESS",
          "OLD_VALUE": "READ_ONLY_ACCESS",
          "ORG_UNIT_NAME": "Example IO",
          "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
        },
        "type": "CALENDAR_SETTINGS"
      }
)


list_object_type = json.dumps(

     {
          "actor": {
          "email": "user@example.io",
          "profileId": "118111111111111111111"
          },
          "id": {
          "applicationName": "drive",
          "customerId": "D12345",
          "time": "2022-12-20 17:27:47.080000000",
          "uniqueQualifier": "-7312729053723258069"
          },
          "ipAddress": "12.12.12.12",
          "kind": "admin#reports#activity",
          "name": "rename",
          "parameters": {
          "actor_is_collaborator_account": None,
          "billable": True,
          "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
          "doc_title": "Document Title- Found Here",
          "doc_type": "presentation",
          "is_encrypted": None,
          "new_value": [
              "Document Title- Found Here"
          ],
          "old_value": [
              "Document Title- Old"
          ],
          "owner": "user@example.io",
          "owner_is_shared_drive": None,
          "owner_is_team_drive": None,
          "primary_event": True,
          "visibility": "private"
          },
          "type": "access"
      }

)

access_event = json.dumps(
      {
        'p_row_id': '111222',
        'actor': {'email': 'bobert@example.com'},
        'id': {'applicationName': 'drive'},
        'events': [
          {
            'type': 'access',
            'name': 'download'
          }
        ]
      }  
)

modify_event_without_over_visibility = json.dumps(
      {
        'p_row_id': '111222',
        'actor': {'email': 'bobert@example.com'},
        'id': {'applicationName': 'drive'},
        'events': [
          {
            'type': 'access',
            'name': 'edit',
            'parameters': [{'name': 'visibility', 'value': 'private'}]
          }
        ]
      }
)

overly_visible_doc_modified = json.dumps(
      {
        'p_row_id': '111222',
        'actor': {'email': 'bobert@example.com'},
        'id': {'applicationName': 'drive'},
        'events': [
          {
            'type': 'access',
            'name': 'edit',
            'parameters': [
                {
                  'name': 'visibility', 
                  'value': 'people_with_link'
                },
                {
                  'name':'doc_title', 
                  'value':'my shared document'
                }
              ]
          }
        ]
      }
)
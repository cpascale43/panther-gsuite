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

normal_login = json.dumps(
      {
        "id": {
          "applicationName": "login",
        },
        "actor": {
          "email": "homer.simpson@example.com",
        },
        "type": "login",
        "name": "login_success",
        "parameters": {
          "is_suspicious": "null",
          "login_challenge_method": [
              "none"
          ],
        },
      }
)

gov_backed_warning = json.dumps(
      {
        "id": {
          "applicationName": "login",
        },
        "actor": {
          "email": "homer.simpson@example.com",
        },
        "type": "login",
        "name": "gov_attack_warning",
        "parameters": {
          "is_suspicious": "null",
          "login_challenge_method": [
              "none"
          ],
        },
      }
)

normal_mobile_event = json.dumps(
      {
        "id": {
          "applicationName": "mobile",
        },
        "actor": {
          "callerType": "USER",
          "email": "homer.simpson@example.io",
        },
        "type": "device_updates",
        "name": "DEVICE_SYNC_EVENT",
        "parameters": {
          "USER_EMAIL": "homer.simpson@example.io"
        },
      }
)

suspicious_activity = json.dumps(
      {
        "id": {
          "applicationName": "mobile",
        },
        "actor": {
          "callerType": "USER",
          "email": "homer.simpson@example.io",
        },
        "type": "device_updates",
        "name": "SUSPICIOUS_ACTIVITY_EVENT",
        "parameters": {
          "USER_EMAIL": "homer.simpson@example.io"
       },
      }
)

advanced_protection_enabled = json.dumps(
        {
        "id": {
          "applicationName": "user_accounts",
        },
        "actor": {
          "callerType": "USER",
          "email": "homer.simpson@example.com"
        },
        "type": "titanium_change",
        "name": "titanium_enroll",
      }
)

advanced_protection_disabled = json.dumps(
      {
        "id": {
          "applicationName": "user_accounts",
        },
        "actor": {
          "callerType": "USER",
          "email": "homer.simpson@example.com"
        },
        "type": "titanium_change",
        "name": "titanium_unenroll",
      }
)

non_triggered_rule = json.dumps(
      {
        "id": {
          "applicationName": "rules"
        },
        "actor": {
          "email": "some.user@somedomain.com"
        },
        "parameters": {
          "severity": "HIGH",
          "triggered_actions": None
        },
      }
)

high_severity_rule = json.dumps(
      {
        "id": {
          "applicationName": "rules"
        },
        "actor": {
          "email": "some.user@somedomain.com"
        },
        "parameters": {
          "data_source": "DRIVE",
          "severity": "HIGH",
          "triggered_actions": [
            {
              "action_type": "DRIVE_UNFLAG_DOCUMENT"
            }
          ]
        }
      }
)

medium_severity_rule = json.dumps(
      {
        "id": {
          "applicationName": "rules"
        },
        "actor": {
          "email": "some.user@somedomain.com"
        },
        "parameters": {
          "data_source": "DRIVE",
          "severity": "MEDIUM",
          "triggered_actions": [
            {
              "action_type": "DRIVE_UNFLAG_DOCUMENT"
            }
          ]
        }
      }
)

low_severity_rule = json.dumps(    
      {
        "id": {
          "applicationName": "rules"
        },
        "actor": {
          "email": "some.user@somedomain.com"
        },
        "parameters": {
          "severity": "LOW",
          "triggered_actions": [
            {
              "action_type": "DRIVE_UNFLAG_DOCUMENT"
            }
          ]
        }
      }
)

high_severity_rule_with_rule_name = json.dumps(
      {
        "id": {
          "applicationName": "rules"
        },
        "actor": {
          "email": "some.user@somedomain.com"
        },
        "parameters": {
          "severity": "HIGH",
          "rule_name": "CEO Impersonation",
          "triggered_actions": [
            {
              "action_type": "MAIL_MARK_AS_PHISHING"
            }
          ]
        }
      }
)

login_with_approved_type =  json.dumps(
      {
        "id": {
          "applicationName": "login",
        },
        "actor": {
          "email": "some.user@somedomain.com"
        },
        "type": "login",
        "name": "login_success",
        "parameters": {
          "login_type": "saml"
        },
      }
)

login_with_unapproved_type = json.dumps(
      {
        "id": {
          "applicationName": "login",
        },
        "actor": {
          "email": "some.user@somedomain.com"
        },
        "type": "login",
        "name": "login_success",
        "parameters": {
          "login_type": "turbo-snail"
        },
      }
)

non_login_event = json.dumps(
      {
        "id": {
          "applicationName": "logout",
        },
        "actor": {
          "email": "some.user@somedomain.com"
        },
        "type": "login",
        "name": "login_success",
        "parameters": {
          "login_type": "saml"
        },
      }
)

saml_login_event = json.dumps(
      {
        "actor": {
          "email": "some.user@somedomain.com",
        },
        "id": {
          "applicationName": "saml",
          "time": "2022-05-26 15:26:09.421000000",
        },
        "ipAddress": "10.10.10.10",
        "kind": "admin#reports#activity",
        "name": "login_success",
        "parameters": {
          "application_name": "Some SAML Application",
          "initiated_by": "sp",
          "orgunit_path": "/SomeOrgUnit",
          "saml_status_code": "SUCCESS_URI"
        },
        "type": "login"
      }
)

dangerous_share_of_known_doc_with_a_missing_user  =  json.dumps(
      {
         "kind":"admin#reports#activity",
         "id":{
            "time":"2020-09-07T15:50:49.617Z",
            "uniqueQualifier":"1111111111111111111",
            "applicationName":"drive",
            "customerId":"C010qxghg"
         },
         "actor":{
            "email":"example@acme.com",
            "profileId":"1111111111111111111"
         },
         "events":[
            {
               "type":"acl_change",
               "name":"change_user_access",
               "parameters":[
                  {
                     "name":"primary_event",
                     "boolValue":True
                  },
                  {
                     "name":"visibility_change",
                     "value":"external"
                  },
                  {
                     "name":"target_user",
                     "value":"outside@acme.com"
                  },
                  {
                     "name":"old_visibility",
                     "value":"private"
                  },
                  {
                     "name":"doc_id",
                     "value":"1111111111111111111"
                  },
                  {
                     "name":"doc_type",
                     "value":"document"
                  },
                  {
                     "name":"doc_title",
                     "value":"Document Title Primary"
                  },
                  {
                     "name":"visibility",
                     "value":"shared_externally"
                  },
                  {
                     "name":"originating_app_id",
                     "value":"1111111111111111111"
                  },
                  {
                     "name":"owner_is_shared_drive",
                     "boolValue":False
                  },
                  {
                     "name":"owner_is_team_drive",
                     "boolValue":False
                  },
                  {
                     "name":"old_value",
                     "multiValue":[
                        "none"
                     ]
                  },
                  {
                     "name":"new_value",
                     "multiValue":[
                        "can_edit"
                     ]
                  }
               ]
            }
         ]
      }
)

dangerous_share_of_unknown_doc  =  json.dumps(
      {
         "kind":"admin#reports#activity",
         "id":{
            "time":"2020-09-07T15:50:49.617Z",
            "uniqueQualifier":"1111111111111111111",
            "applicationName":"drive",
            "customerId":"C010qxghg"
         },
         "actor":{
            "email":"example@acme.com",
            "profileId":"1111111111111111111"
         },
         "events":[
            {
               "type":"acl_change",
               "name":"change_user_access",
               "parameters":[
                  {
                     "name":"primary_event",
                     "boolValue":True
                  },
                  {
                     "name":"visibility_change",
                     "value":"external"
                  },
                  {
                     "name":"target_user",
                     "value":"alice@external.com"
                  },
                  {
                     "name":"old_visibility",
                     "value":"private"
                  },
                  {
                     "name":"doc_id",
                     "value":"1111111111111111111"
                  },
                  {
                     "name":"doc_type",
                     "value":"document"
                  },
                  {
                     "name":"doc_title",
                     "value":"Untitled document"
                  },
                  {
                     "name":"visibility",
                     "value":"shared_externally"
                  },
                  {
                     "name":"originating_app_id",
                     "value":"1111111111111111111"
                  },
                  {
                     "name":"owner_is_shared_drive",
                     "boolValue":False
                  },
                  {
                     "name":"owner_is_team_drive",
                     "boolValue":False
                  },
                  {
                     "name":"old_value",
                     "multiValue":[
                        "none"
                     ]
                  },
                  {
                     "name":"new_value",
                     "multiValue":[
                        "can_edit"
                     ]
                  }
               ]
            }
         ]
      }
)

share_allowed_by_exception  =  json.dumps(
      {
         "kind":"admin#reports#activity",
         "id":{
            "time":"2020-07-07T15:50:49.617Z",
            "uniqueQualifier":"1111111111111111111",
            "applicationName":"drive",
            "customerId":"C010qxghg"
         },
         "actor":{
            "email":"alice@acme.com",
            "profileId":"1111111111111111111"
         },
         "events":[
            {
               "type":"acl_change",
               "name":"change_user_access",
               "parameters":[
                  {
                     "name":"primary_event",
                     "boolValue":True
                  },
                  {
                     "name":"billable",
                     "boolValue":True
                  },
                  {
                     "name":"visibility_change",
                     "value":"external"
                  },
                  {
                     "name":"target_domain",
                     "value":"acme.com"
                  },
                  {
                     "name":"old_visibility",
                     "value":"private"
                  },
                  {
                     "name":"doc_id",
                     "value":"1111111111111111111"
                  },
                  {
                     "name":"doc_type",
                     "value":"document"
                  },
                  {
                     "name":"doc_title",
                     "value":"Document Title Pattern"
                  },
                  {
                     "name":"visibility",
                     "value":"shared_externally"
                  },
                  {
                     "name":"originating_app_id",
                     "value":"1111111111111111111"
                  },
                  {
                     "name":"owner_is_shared_drive",
                     "boolValue":False
                  },
                  {
                     "name":"owner_is_team_drive",
                     "boolValue":False
                  },
                  {
                     "name":"old_value",
                     "multiValue":[
                        "none"
                     ]
                  },
                  {
                     "name":"new_value",
                     "multiValue":[
                        "people_within_domain_with_link"
                     ]
                  }
               ]
            }
         ]
      }
)

normal_login_event = json.dumps({'id': {'applicationName': 'login'}, 'type': 'login', 'name': 'logout', 'parameters': {'login_type': 'saml'}})
account_warning_not_for_password_leaked = json.dumps({'id': {'applicationName': 'login'}, 'type': 'account_warning', 'name': 'account_disabled_spamming', 'parameters': {'affected_email_address': 'homer.simpson@example.com'}})
account_warning_for_password_leaked = json.dumps({'id': {'applicationName': 'login'}, 'type': 'account_warning', 'name': 'account_disabled_password_leak', 'parameters': {'affected_email_address': 'homer.simpson@example.com'}})
small_number_of_failed_logins = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'FAILED_PASSWORD_ATTEMPTS_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io', 'FAILED_PASSWD_ATTEMPTS': 2}})
multiple_failed_login_attempts_with_string_type = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'FAILED_PASSWORD_ATTEMPTS_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io', 'FAILED_PASSWD_ATTEMPTS': '100'}})
multiple_failed_login_attempts_with_int_type = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'FAILED_PASSWORD_ATTEMPTS_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io', 'FAILED_PASSWD_ATTEMPTS': 100}})


forwarding_to_external_address = json.dumps(
{
      "id": {
          "applicationName": "user_accounts",
          "customerId": "D12345",
        },
        "actor": {
          "email": "homer.simpson@.springfield.io",
        },
        "type": "email_forwarding_change",
        "name": "email_forwarding_out_of_domain",
        "parameters": {
          "email_forwarding_destination_address": "HSimpson@gmail.com"
        },
      }
)

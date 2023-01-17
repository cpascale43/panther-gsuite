
test_dict = {
        "id": {
            "applicationName": "login",
        },
        "kind": "admin#reports#activity",
        "type": "account_warning",
        "name": "suspicious_login",
        "parameters": {
            "affected_email_address": "bobert@ext.runpanther.io"
        },
    }


def _deep_equal(event, path, value):
    import functools
    import collections

    print(path)

    print('split path ------------>')
    print(path.split("."))
    keys = path.split(".")
    
    print('keys should be id, kind, type, name, parameters------------->')
    print(keys)

    actual = functools.reduce(
        lambda d, key: d.get(key, None)
        if isinstance(d, collections.abc.Mapping)
        else None,
        keys,
        event,
    )

    print('actual should be login -------------->')
    print(actual)

    return bool(actual == value)


print(_deep_equal(test_dict, "id.applicationName", "login"))


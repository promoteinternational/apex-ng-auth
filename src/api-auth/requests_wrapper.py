import json
from datetime import datetime

import requests
from Crypto.PublicKey import RSA


def method_with_body(name, url, private_key, public_key, data, json=None, headers={}, **kwargs):
    timestamp = datetime.utcnow().isoformat()
    encoded_body = json.dumps(json if json else data)
    key = RSA.importKey(private_key)
    signature = key.encrypt((public_key + encoded_body + timestamp).encode())
    headers.update({"Signature": signature, "API-Token": f"Timestamp {timestamp}"})
    result = requests.__getattribute__(name)(url=url, data=data, json=json, headers=headers, **kwargs)
    body = json.loads(result.content)
    return result


def method_without_body(name, url, private_key, public_key, headers={}, **kwargs):
    timestamp = datetime.utcnow().isoformat()
    encoded_body = ""
    key = RSA.importKey(private_key)
    signature = key.encrypt((public_key + encoded_body + timestamp).encode())
    headers.update({"Signature": signature, "API-Token": f"Timestamp {timestamp}"})
    result = requests.__getattribute__(name)(url=url, data=data, json=json, headers=headers, **kwargs)
    body = json.loads(result.content)
    return result


def post(url, private_key, public_key, data, json=None, headers={}, **kwargs):
    return method_with_body("post", url, private_key, public_key, data, json, headers, **kwargs)


def get(url, private_key, public_key, headers={}, **kwargs):
    return method_without_body("get", url, private_key, public_key, {}, **kwargs)


def put(url, private_key, public_key, data=None, json=None, headers={}, **kwargs):
    return method_with_body("put", url, private_key, public_key, data, json, headers, **kwargs)


def patch(url, private_key, public_key, data=None, json=None, headers={}, **kwargs):
    return method_with_body("patch", url, private_key, public_key, data, json, headers, **kwargs)


def delete(url, private_key, public_key, headers={}, **kwargs):
    return method_without_body("delete", url, private_key, public_key, {}, **kwargs)
from base64 import b64encode
from datetime import datetime
from hashlib import sha256

import requests


def method_with_body(name, url, private_key, public_key, data, json=None, headers={}, **kwargs):
    timestamp = datetime.utcnow().isoformat()
    encoded_body = sha256(json.dumps(json if json else data).encode()).digest()
    signature = sha256((public_key + str(encoded_body) + timestamp + private_key).encode()).digest()

    headers.update({"Signature": b64encode(signature).decode(),
                    "API-Token": f"Timestamp {timestamp}",
                    "Public-Key": b64encode(public_key)})

    result = requests.__getattribute__(name)(url=url, data=data, json=json, headers=headers, **kwargs)
    return result


def method_without_body(name, url, private_key, public_key, headers={}, **kwargs):
    timestamp = datetime.utcnow().isoformat()
    encoded_body = sha256(b"").digest()
    signature = sha256((public_key + str(encoded_body) + timestamp + private_key).encode()).digest()

    headers.update({"Signature": b64encode(signature).decode(),
                    "API-Token": f"Timestamp {timestamp}",
                    "Public-Key": b64encode(public_key)})

    result = requests.__getattribute__(name)(url=url, headers=headers, **kwargs)
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

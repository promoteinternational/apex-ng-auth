import hashlib
import json
from base64 import b64encode

from datetime import datetime


def create_request_headers(key_pair, data):
    timestamp = datetime.utcnow().isoformat()
    encoded_body = hashlib.sha256(json.dumps(data).encode()).digest()
    signature = hashlib.sha256((key_pair.public_key +
                                str(encoded_body) +
                                timestamp +
                                key_pair.private_key).encode()).digest()
    return {
        "Signature": b64encode(signature).decode(),
        "Timestamp": timestamp,
        "API-Token": b64encode(key_pair.public_key.encode()).decode()
    }

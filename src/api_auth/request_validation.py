import hashlib
import json

from base64 import b64encode, b64decode


def get_validation_headers(request):
    public_key_header = request.META.get("API-Token")
    public_key = b64decode(public_key_header.decode())
    return {
        "Public-Key": public_key,
        "Timestamp": request.META.get("Timestamp"),
        "Signature": request.META.get("Signature")
    }


def is_signature_valid(request, key_pair, timestamp, actual_signature):
    if request.method == "GET":
        encoded_body = hashlib.sha256(b"").digest()
    else:
        encoded_body = hashlib.sha256(json.dumps(request.POST).encode()).digest()

    signature = hashlib.sha256(
        (key_pair.public_key +
         str(encoded_body) +
         timestamp +
         key_pair.private_key).encode()).digest()

    return actual_signature == b64encode(signature).decode()

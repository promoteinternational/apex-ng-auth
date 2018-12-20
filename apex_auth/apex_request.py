import hashlib
import json
from base64 import b64encode, b64decode
from datetime import datetime
from typing import Optional


class ApexRequest:
    @staticmethod
    def create_request_headers(public_key: str, private_key: str, data: Optional[dict]) -> dict:
        timestamp = datetime.utcnow().isoformat()

        encoded_body = hashlib.sha256((json.dumps(data if data is not None else {})).encode()).hexdigest()

        signature = hashlib.sha256((public_key +
                                    encoded_body +
                                    timestamp +
                                    private_key).encode()).hexdigest().encode()
        return {
            "Signature": b64encode(signature).decode(),
            "Timestamp": timestamp,
            "API-Token": b64encode(public_key.encode()).decode()
        }

    @staticmethod
    def get_validation_headers(headers: dict) -> dict:
        if ApexRequest.check_headers(headers, ["API-Token", "Timestamp", "Signature"]):
            public_key_header = headers.get("API-Token")
            public_key = b64decode(public_key_header).decode()
            return {
                "Public-Key": public_key,
                "Timestamp": headers.get("Timestamp"),
                "Signature": headers.get("Signature")
            }
        elif ApexRequest.check_headers(headers, ["HTTP_API_TOKEN", "HTTP_TIMESTAMP", "HTTP_SIGNATURE"]):
            public_key_header = headers.get("HTTP_API_TOKEN")
            public_key = b64decode(public_key_header).decode()
            return {
                "Public-Key": public_key,
                "Timestamp": headers.get("HTTP_TIMESTAMP"),
                "Signature": headers.get("HTTP_SIGNATURE")
            }
        else:
            return {}

    @staticmethod
    def signature_is_valid(data: Optional[dict], public_key: str, private_key: str, timestamp: str,
                           actual_signature: str) -> bool:
        encoded_body = hashlib.sha256(json.dumps(data if data is not None else {}).encode()).hexdigest()

        signature = hashlib.sha256(
            (public_key +
             encoded_body +
             timestamp +
             private_key).encode()).hexdigest().encode()

        return actual_signature == b64encode(signature).decode()

    @staticmethod
    def check_headers(headers, required_headers):
        return all([headers.get(header) for header in required_headers])

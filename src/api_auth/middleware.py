import hashlib
import json
from base64 import b64decode, b64encode
from datetime import datetime
from hashlib import sha256

from Crypto.PublicKey import RSA
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.middleware.common import MiddlewareMixin

from .models.key_pair import KeyPair


class PortalAuthMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest):
        key_pair = self.get_public_key(request)

        if request.META.get("API-Token") and "Timestamp" in request.META.get("API-Token"):
            if request.method not in ["GET", "DELETE"]:
                encoded_body = hashlib.sha256(request.body.encode()).digest()
            else:
                encoded_body = hashlib.sha256(b"").digest()

            timestamp = request.META.get("API-Token").split(" ")[-1]
            actual_signature = request.META.get("Signature")
            signature = sha256((key_pair.public_key + str(encoded_body) + timestamp + key_pair.private_key).encode()).digest()

            if actual_signature != b64encode(signature).decode():
                return HttpResponseBadRequest()

    def process_response(self, request: HttpRequest, response: HttpResponse):
        key_pair = self.get_public_key(request)

        if request.META.get("API-Token") and "Timestamp" in request.META.get("API-Token"):
            encoded_body = hashlib.sha256(response.content).digest()
            timestamp = datetime.utcnow().isoformat()
            signature = sha256((key_pair.public_key + str(encoded_body) + timestamp + key_pair.private_key).encode()).digest()
            response.__setitem__("Public-Key", b64encode(key_pair.public_key.encode()))
            response.__setitem__("Signature", b64encode(signature).decode())
            response.__setitem__("API-Token", f"Timestamp {timestamp}")

        return response

    def get_public_key(self, request):
        public_key_header = request.META.get("Public-Key")
        public_key = b64decode(public_key_header.decode())
        key_pair = KeyPair.objects.filter(public_key=public_key.decode()).first()
        return key_pair

import hashlib
import json
from base64 import b64decode, b64encode
from hashlib import sha256

from django.http import HttpRequest, HttpResponseBadRequest

from .models.key_pair import KeyPair


class PortalAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        self.process_request(request)
        response = self.get_response(request)
        return response

    def process_request(self, request: HttpRequest):
        key_pair = self.get_public_key(request)

        if request.META.get("API-Token") and "Timestamp" in request.META.get("API-Token"):
            if request.method == "GET":
                encoded_body = hashlib.sha256(b"").digest()
            else:
                encoded_body = hashlib.sha256(json.dumps(request.POST).encode()).digest()

            timestamp = request.META.get("API-Token").split(" ")[-1]
            actual_signature = request.META.get("Signature")
            signature = sha256(
                (key_pair.public_key + str(encoded_body) + timestamp + key_pair.private_key).encode()).digest()

            if actual_signature != b64encode(signature).decode():
                return HttpResponseBadRequest()

    def get_public_key(self, request):
        public_key_header = request.META.get("Public-Key")
        public_key = b64decode(public_key_header.decode())
        key_pair = KeyPair.objects.filter(public_key=public_key.decode()).first()
        return key_pair

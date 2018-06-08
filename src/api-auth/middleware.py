import hashlib
import json
from base64 import b64decode, b64encode
from datetime import datetime

from Crypto.PublicKey import RSA
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest

from .models.key_pair import KeyPair


class PortalAuthMiddleware:
    def __init__(self, get_response):
        """
        Save the get response function

        :param get_response: the function to be called after the processing of the request
        """
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_request(self, request: HttpRequest):
        key_pair = self.get_public_key(request)
        encoded_body = ""
        if request.META.get("API-Token") and "Timestamp" in request.META("API-Token"):
            if request.method not in ["GET", "DELETE"]:
                encoded_body = hashlib.sha256(json.dumps(request.body).encode())
            timestamp = request.META.get("API-Token").split(" ")[-1]
            actual_signature = request.META.get("Signature")
            private_key = RSA.importKey(key_pair.private_key)
            signature = private_key.encrypt((key_pair.public_key + encoded_body + timestamp).encode())
            if actual_signature != signature:
                return HttpResponseBadRequest()

    def process_response(self, request: HttpRequest, response: HttpResponse):
        key_pair = self.get_public_key(request)
        encoded_body = ""
        if request.META.get("API-Token") and "Timestamp" in request.META("API-Token"):
            if request.method not in ["GET", "DELETE"]:
                encoded_body = hashlib.sha256(json.dumps(response.content).encode())
            timestamp = datetime.utcnow().isoformat()
            private_key = RSA.importKey(key_pair.private_key)
            signature = private_key.encrypt((key_pair.public_key + encoded_body + timestamp).encode())
            body = json.loads(response.content)
            response.content = json.dumps(body).encode()
            response.__setitem__("Public-Key", b64encode(key_pair.public_key))
            response.__setitem__("Signature", f"{signature}")
            response.__setitem__("API-Token", f"Timestamp {timestamp}")
        return response

    def get_public_key(self, request):
        public_key_header = request.META.get("Public-Key")
        public_key = b64decode(public_key_header)
        key_pair = KeyPair.objects.filter(public_key=public_key).first()
        return key_pair

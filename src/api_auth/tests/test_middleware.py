from base64 import b64encode
from datetime import datetime
from hashlib import sha256

from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.test import TestCase

from api_auth.middleware import PortalAuthMiddleware
from api_auth.models import KeyPair


class TestMiddleware(TestCase):
    def setUp(self):
        key_pair = KeyPair.generate_key_pair("test")
        key_pair.save()
        self.private_key = key_pair.private_key
        self.public_key = key_pair.public_key

    def test_process_request_get(self):
        timestamp = datetime.utcnow().isoformat()
        encoded_body = sha256(b"").digest()
        signature = sha256((self.public_key + str(encoded_body) + timestamp + self.private_key).encode()).digest()
        request = HttpRequest()
        request.META = {
            "API-Token": f"Timestamp {timestamp}",
            "Public-Key": b64encode(self.public_key.encode()),
            "Signature": b64encode(signature).decode(),
        }
        request.method = "GET"

        middleware = PortalAuthMiddleware()
        middleware.process_request(request)

    def test_process_response(self):
        timestamp = datetime.utcnow().isoformat()
        signature = sha256((self.public_key + "" + timestamp + self.private_key).encode()).digest()
        request = HttpRequest()
        request.META = {
            "API-Token": f"Timestamp {timestamp}",
            "Public-Key": b64encode(self.public_key.encode()),
            "Signature": b64encode(signature).decode(),
        }
        request.method = "GET"
        response = HttpResponse()
        response.content = b'{"hello": "world"}'

        middleware = PortalAuthMiddleware()
        new_response = middleware.process_response(request, response)

        self.assertIsNotNone(new_response.get('API-Token'))
        self.assertIsNotNone(new_response.get('Signature'))
        self.assertEqual(len(new_response.get('API-Token').split(" ")), 2)

        new_timestamp = new_response.get('API-Token').split(" ")[1]
        encoded_body = sha256(new_response.content).digest()
        new_signature = sha256(
            (self.public_key + str(encoded_body) +
             new_timestamp + self.private_key).encode()).digest()

        self.assertEqual(b64encode(new_signature).decode(), new_response.get('Signature'))



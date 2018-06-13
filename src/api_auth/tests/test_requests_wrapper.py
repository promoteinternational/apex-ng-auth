import mock
import requests
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.test import TestCase

from api_auth.middleware import PortalAuthMiddleware
from api_auth.models import KeyPair
from api_auth.utils import requests_wrapper


def mock_response_get(url, headers=None, data=None, json=None, **kwargs):
    request = HttpRequest()
    request.META = headers
    request.method = "GET"

    middleware = PortalAuthMiddleware()
    result = middleware.process_request(request)
    assert result is None
    response = HttpResponse()
    response.content = b'{"hello": "world"}'

    middleware = PortalAuthMiddleware()
    middleware_response = middleware.process_response(request, response)
    new_response = requests.Response()
    new_response.status_code = 200
    new_response.headers = {value[0]: value[1] for key, value in middleware_response._headers.items()}
    new_response._content = middleware_response.content
    return new_response


def mock_response_post(url, headers=None, data=None, json=None, **kwargs):
    request = HttpRequest()
    request.META = headers
    request.method = "POST"
    request.POST = json if json else data

    middleware = PortalAuthMiddleware()
    result = middleware.process_request(request)
    assert result is None
    response = HttpResponse()
    response.content = b'{"hello": "world"}'

    middleware = PortalAuthMiddleware()
    middleware_response = middleware.process_response(request, response)
    new_response = requests.Response()
    new_response.status_code = 200
    new_response.headers = {value[0]: value[1] for key, value in middleware_response._headers.items()}
    new_response._content = middleware_response.content
    return new_response


class TestRequestWrapper(TestCase):
    url = "http://127.0.0.1:8000/"
    data = {"key": "value"}

    def setUp(self):
        key_pair = KeyPair.generate_key_pair("test")
        key_pair.save()
        self.private_key = key_pair.private_key
        self.public_key = key_pair.public_key

    @mock.patch("requests.get", mock_response_get)
    def test_method_get(self):
        response = requests_wrapper.get(self.url, self.private_key, self.public_key)
        self.assertEqual(response.text, '{"hello": "world"}')
        for header in ["API-Token", "Signature", "Public-Key"]:
            self.assertIn(header, response.headers)
            self.assertIsNotNone(response.headers.get(header))

    @mock.patch("requests.post", mock_response_post)
    def test_method_post(self):
        response = requests_wrapper.post(self.url, self.private_key, self.public_key, json={"hello": "world"})
        self.assertEqual(response.text, '{"hello": "world"}')
        for header in ["API-Token", "Signature", "Public-Key"]:
            self.assertIn(header, response.headers)
            self.assertIsNotNone(response.headers.get(header))

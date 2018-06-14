import json

from django.http import HttpResponseBadRequest, HttpResponse
from django.views.generic import View

from api_auth.models import KeyPair


class KeyPairGenerateView(View):
    def post(self, request, *args, **kwargs):
        name = request.POST.get("name")
        if not name:
            return HttpResponseBadRequest({"name": ["Name is not provided."]})
        key_pair_model = KeyPair.generate_key_pair(name)
        data = {
            "public_key": key_pair_model.public_key,
            "private_key": key_pair_model.private_key
        }
        return HttpResponse(content=json.dumps(data),
                            content_type="application/json",
                            status=201)

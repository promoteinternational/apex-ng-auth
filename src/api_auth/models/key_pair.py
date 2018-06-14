from django.db import models
from Crypto.PublicKey import RSA
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import get_user_model


from django.conf import settings


class KeyPair(models.Model):
    name = models.CharField(_("Name of the assigned API"),
                            max_length=100,
                            help_text="The name of the API that is assigned to this key pair")
    public_key = models.TextField()
    private_key = models.TextField()
    user = models.OneToOneField(get_user_model(),
                                on_delete=models.CASCADE,
                                related_name="key_pair")

    @classmethod
    def generate_key_pair(cls, name):
        user = get_user_model().objects.create(
            username=name,
            email=f'{name}@apexclient.com'
        )
        key_pair = RSA.generate(settings.KEY_LENGTH)
        private_key = key_pair.exportKey()
        public_key = key_pair.publickey().exportKey()
        model = cls.objects.create(
            name=name,
            private_key=private_key.decode(),
            public_key=public_key.decode(),
            user=user
        )
        return model

    class Meta:
        verbose_name = _("key_pair")
        verbose_name_plural = _("key_pairs")

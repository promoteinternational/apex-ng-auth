from django.db import models
import hashlib
from django.utils.translation import ugettext_lazy as _


class KeyPair(models.Model):
    name = models.CharField(_("Name of the assigned API"),
                            max_length=100,
                            help_text="The name of the API that is assigned to this key pair")
    public_key = models.TextField()
    private_key = models.TextField()

    @property
    def hashed_public_key(self):
        return hashlib.sha256(self.public_key.encode())

    class Meta:
        verbose_name = _("key_pair")
        verbose_name_plural = _("key_pairs")

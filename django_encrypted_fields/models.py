import json

from django.conf import settings
from django.db import models
from django.utils.functional import cached_property

from cryptography.fernet import Fernet, InvalidToken


class BaseEncryptedField:
    @cached_property
    def keys(self):
        return [key.encode("utf-8") for key in settings.MODEL_ENCRYPTION_KEYS]

    @cached_property
    def fernet_keys(self):
        return [Fernet(key) for key in self.keys]

    def _encrypt(self, value) -> str:
        return self.fernet_keys[0].encrypt(bytes(value, "utf-8")).decode("utf-8")

    def _decrypt(self, value) -> str:
        for fernet in self.fernet_keys:
            try:
                return fernet.decrypt(bytes(value, "utf-8")).decode("utf-8")
            except InvalidToken:
                continue
        raise ValueError("Decryption failed for all provided keys.")


class EncryptedTextField(BaseEncryptedField, models.TextField):
    def get_prep_value(self, value):
        return self._encrypt(value)

    def from_db_value(self, value, expression, connection):
        return self.to_python(value)

    def to_python(self, value):
        if (
            value is None
            or not isinstance(value, str)
            or hasattr(self, "_already_decrypted")
        ):  # fmt: skip
            return value

        return self._decrypt(value)

    def clean(self, value, model_instance):
        self._already_decrypted = True
        return_value = super().clean(value, model_instance)
        del self._already_decrypted
        return return_value


class EncryptedJSONField(BaseEncryptedField, models.JSONField):
    def __init__(self, encrypt_all=False, target_fields=None, **kwargs):
        if target_fields and encrypt_all:
            raise ValueError("Cannot specify both `target_fields` and `encrypt_all`.")
        if not target_fields and not encrypt_all:
            raise ValueError("Must specify either `target_fields` or `encrypt_all`.")

        self.encrypt_all = encrypt_all
        self.target_fields = target_fields
        super().__init__(**kwargs)

    def _encrypt_or_decrypt_all(self, value, encrypt):
        return self._encrypt(json.dumps(value)) if encrypt else json.loads(self._decrypt(value))

    def _encrypt_or_decrypt_target_field(self, value, encrypt):
        if isinstance(value, (dict, list)):
            return self._encrypt_or_decrypt_all(value, encrypt)
        return self._encrypt(value) if encrypt else self._decrypt(value)

    def _encrypt_or_decrypt_dict(self, value: dict, encrypt):
        return_value = value.copy()  # Do not modify the original value.

        for target_key, field in return_value.items():
            if target_key in self.target_fields:
                return_value[target_key] = self._encrypt_or_decrypt_target_field(field, encrypt)
            else:
                return_value[target_key] = self._encrypt_or_decrypt_value(field, encrypt)

        return return_value

    def _encrypt_or_decrypt_list(self, value: list, encrypt):
        return [self._encrypt_or_decrypt_value(item, encrypt) for item in value]

    def _encrypt_or_decrypt_value(self, value, encrypt):
        if isinstance(value, dict):
            return self._encrypt_or_decrypt_dict(value, encrypt)
        elif isinstance(value, list):
            return self._encrypt_or_decrypt_list(value, encrypt)

        return value

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.encrypt_all:
            kwargs["encrypt_all"] = self.encrypt_all
        if self.target_fields:
            kwargs["target_fields"] = self.target_fields
        return name, path, args, kwargs

    def get_internal_type(self):
        if self.encrypt_all:
            return "TextField"
        return "JSONField"

    def get_prep_value(self, value):
        if self.encrypt_all:
            return self._encrypt_or_decrypt_all(value, encrypt=True)
        return self._encrypt_or_decrypt_value(value, encrypt=True)

    def from_db_value(self, value, expression, connection):
        return self.to_python(value)

    def to_python(self, value):
        if (
            value is None
            or not isinstance(value, str)
            or hasattr(self, "_already_decrypted")
        ):  # fmt: skip
            return value

        if self.encrypt_all:
            return self._encrypt_or_decrypt_all(value, encrypt=False)
        return self._encrypt_or_decrypt_value(json.loads(value), encrypt=False)

    def clean(self, value, model_instance):
        self._already_decrypted = True
        return_value = super().clean(value, model_instance)
        del self._already_decrypted
        return return_value

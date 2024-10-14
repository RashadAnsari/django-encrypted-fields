from django.core.management.base import BaseCommand

from cryptography.fernet import Fernet


class Command(BaseCommand):
    help = "Generate a new Fernet key."

    def handle(self, *args, **kwargs):
        key = Fernet.generate_key().decode("utf-8")
        self.stdout.write(self.style.SUCCESS(f"Fernet key: {key}"))

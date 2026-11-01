import secrets
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction
from fleet.models import LocalAccountState


class Command(BaseCommand):
    help = "Create the default local admin with a one-time generated password. Never resets existing accounts."

    def handle(self, *args, **options):
        users = get_user_model().objects
        if users.filter(is_superuser=True, is_active=True, is_staff=True).exists():
            self.stdout.write("An active administrator already exists; credentials left unchanged.")
            return
        password = secrets.token_urlsafe(24)
        try:
            with transaction.atomic():
                if users.filter(username="admin").exists():
                    raise CommandError("The username admin is already in use. Create an administrator with createsuperuser; no existing account was changed.")
                user = users.create_superuser(username="admin", password=password)
                LocalAccountState.objects.create(user=user, must_change_password=True)
        except IntegrityError as exc:
            raise CommandError("Administrator initialization raced with another setup. Rerun setup; existing accounts were left unchanged.") from exc
        self.stdout.write("Local administrator created. Save this temporary password; it will not be displayed again.")
        self.stdout.write("Username: admin")
        self.stdout.write("Temporary password: " + password)
        self.stdout.write("You must change this password after signing in. Settings are available from the sidebar.")

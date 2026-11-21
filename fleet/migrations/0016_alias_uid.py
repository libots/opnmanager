import uuid

import django.core.validators
from django.db import migrations, models


def assign_uids(apps, schema_editor):
    Alias = apps.get_model("fleet", "Alias")
    for alias in Alias.objects.filter(uid__isnull=True):
        alias.uid = uuid.uuid4()
        alias.save(update_fields=["uid"])


class Migration(migrations.Migration):
    dependencies = [
        ("fleet", "0015_icmp6_type_names"),
    ]

    operations = [
        migrations.AddField(
            model_name="alias",
            name="uid",
            field=models.UUIDField(null=True, editable=False),
        ),
        migrations.RunPython(assign_uids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="alias",
            name="uid",
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AlterField(
            model_name="alias",
            name="description",
            field=models.CharField(
                blank=True, max_length=255, validators=[django.core.validators.MaxLengthValidator(237)]
            ),
        ),
    ]

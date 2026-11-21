import uuid

import django.core.validators
from django.db import migrations, models


def assign_uids(apps, schema_editor):
    InterfaceGroup = apps.get_model("fleet", "InterfaceGroup")
    for group in InterfaceGroup.objects.filter(uid__isnull=True):
        group.uid = uuid.uuid4()
        group.save(update_fields=["uid"])


class Migration(migrations.Migration):
    dependencies = [
        ("fleet", "0016_alias_uid"),
    ]

    operations = [
        migrations.AddField(
            model_name="interfacegroup",
            name="uid",
            field=models.UUIDField(null=True, editable=False),
        ),
        migrations.RunPython(assign_uids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="interfacegroup",
            name="uid",
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AddField(
            model_name="interfacegroup",
            name="no_gui_group",
            field=models.BooleanField(
                default=False,
                help_text="Prevent grouping these members in the interfaces menu section",
                verbose_name="(no) GUI groups",
            ),
        ),
        migrations.AlterField(
            model_name="interfacegroup",
            name="description",
            field=models.CharField(
                blank=True, max_length=255, validators=[django.core.validators.MaxLengthValidator(237)]
            ),
        ),
    ]

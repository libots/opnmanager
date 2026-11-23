from django.db import migrations


def copy_remaining_bindings(apps, schema_editor):
    """Keep the binding of any rule that still uses only the legacy single-interface field.

    0004 copied existing values into Rule.interfaces, but rules created afterwards with
    only Rule.interface (for example by older versions of seed_demo) still relied on it.
    """
    Rule = apps.get_model("fleet", "Rule")
    through = Rule.interfaces.through
    db = schema_editor.connection.alias
    for rule in Rule.objects.using(db).exclude(interface_id=None).iterator():
        through.objects.using(db).get_or_create(rule_id=rule.pk, logicalinterface_id=rule.interface_id)


class Migration(migrations.Migration):
    dependencies = [
        ("fleet", "0017_interfacegroup_uid_no_gui_group"),
    ]

    operations = [
        migrations.RunPython(copy_remaining_bindings, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="rule",
            name="interface",
        ),
    ]

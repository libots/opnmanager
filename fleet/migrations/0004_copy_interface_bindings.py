from django.db import migrations


def copy_bindings(apps, schema_editor):
    Rule = apps.get_model("fleet", "Rule")
    through = Rule.interfaces.through
    for rule in Rule.objects.using(schema_editor.connection.alias).exclude(interface_id=None).iterator():
        through.objects.using(schema_editor.connection.alias).get_or_create(rule_id=rule.pk, logicalinterface_id=rule.interface_id)


class Migration(migrations.Migration):
    dependencies = [("fleet", "0003_alter_alias_options_alter_firewall_options_and_more")]
    operations = [migrations.RunPython(copy_bindings, migrations.RunPython.noop)]

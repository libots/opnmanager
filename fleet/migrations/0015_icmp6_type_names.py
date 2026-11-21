from django.db import migrations

# Earlier versions stored ICMPv6 type numbers, which OPNsense's icmp6type field rejects.
NAMES = {
    "1": "unreach",
    "2": "toobig",
    "3": "timex",
    "4": "paramprob",
    "128": "echoreq",
    "129": "echorep",
    "130": "listqry",
    "131": "listenrep",
    "132": "listendone",
    "133": "routersol",
    "134": "routeradv",
    "135": "neighbrsol",
    "136": "neighbradv",
    "137": "redir",
    "138": "routrrenum",
    "139": "niqry",
    "140": "nirep",
    "200": "mtraceresp",
    "201": "mtrace",
}


def convert(apps, mapping):
    Rule = apps.get_model("fleet", "Rule")
    for rule in Rule.objects.exclude(icmp6_types=""):
        values = [mapping.get(v.strip(), v.strip()) for v in rule.icmp6_types.split(",") if v.strip()]
        rule.icmp6_types = ",".join(values)
        rule.save(update_fields=["icmp6_types"])


def forwards(apps, schema_editor):
    convert(apps, NAMES)


def backwards(apps, schema_editor):
    convert(apps, {name: number for number, name in NAMES.items()})


class Migration(migrations.Migration):
    dependencies = [("fleet", "0014_longer_rule_descriptions")]
    operations = [migrations.RunPython(forwards, backwards)]

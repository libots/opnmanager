import json
from django import forms
from .reconcile import validate_snapshot

class SnapshotImportForm(forms.Form):
    snapshot = forms.FileField(help_text="Normalized JSON snapshot (schema version 1), maximum 5 MiB.")
    def clean_snapshot(self):
        upload = self.cleaned_data["snapshot"]
        if upload.size > 5 * 1024 * 1024:
            raise forms.ValidationError("Snapshot exceeds 5 MiB.")
        try:
            return validate_snapshot(json.load(upload))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise forms.ValidationError("Invalid snapshot JSON: " + str(exc))

from .models import Rule, Alias, LogicalInterface, Firewall, InterfaceGroup
from .choices import ICMP_TYPES, ICMP6_TYPES, PROTOCOLS


class TokenWidget(forms.SelectMultiple):
    def __init__(self, *args, tags=False, **kwargs):
        attrs = kwargs.pop("attrs", {})
        attrs.update({"class": "opn-select", "data-tags": "true" if tags else "false", "style": "min-width:260px;max-width:100%;width:100%"})
        super().__init__(*args, attrs=attrs, **kwargs)
    def format_value(self, value):
        return [v.strip() for v in value.split(",") if v.strip()] if isinstance(value, str) else super().format_value(value)
    def value_from_datadict(self, data, files, name):
        values = super().value_from_datadict(data, files, name) or []
        if isinstance(values, str): values = values.split(",")
        return ",".join(dict.fromkeys(v.strip() for v in values if v.strip()))
    def optgroups(self, name, value, attrs=None):
        choices = list(self.choices)
        known = {str(key) for key, label in choices}
        self.choices = choices + [(v, v) for v in value if v not in known]
        try: return super().optgroups(name, value, attrs)
        finally: self.choices = choices
    class Media:
        css = {"all": ["admin/css/vendor/select2/select2.css"]}
        js = ["admin/js/vendor/jquery/jquery.js", "admin/js/vendor/select2/select2.full.js", "admin/js/jquery.init.js", "selections.js"]


class MultiSelectWidget(TokenWidget):
    def value_from_datadict(self, data, files, name):
        return forms.SelectMultiple.value_from_datadict(self, data, files, name)


class CSVChoicesField(forms.CharField):
    def __init__(self, *args, choices=(), tags=False, **kwargs):
        super().__init__(*args, widget=TokenWidget(choices=choices, tags=tags), **kwargs)
        self.allowed = None if tags else {str(key) for key, label in choices}
    def validate(self, value):
        super().validate(value)
        if self.allowed is not None and any(v not in self.allowed for v in value.split(",") if v):
            raise forms.ValidationError("Choose a supported value.")


class RuleForm(forms.ModelForm):
    protocol = CSVChoicesField(choices=PROTOCOLS, initial="any")
    source = CSVChoicesField(tags=True, initial="any")
    destination = CSVChoicesField(tags=True, initial="any")
    source_port = forms.CharField(required=False, widget=TokenWidget(tags=True))
    destination_port = forms.CharField(required=False, widget=TokenWidget(tags=True))
    icmp_types = CSVChoicesField(choices=ICMP_TYPES, required=False, help_text="IPv4 ICMP types; leave empty for any type.")
    icmp6_types = CSVChoicesField(choices=ICMP6_TYPES, required=False, help_text="IPv6 ICMP types; leave empty for any type.")
    class Meta:
        model = Rule
        exclude = ["interface"]
        widgets = {key: MultiSelectWidget() for key in ("interfaces", "interface_groups", "categories", "firewalls")}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.help_text = field.help_text.split(' Hold down')[0]
        addresses = [("any", "Any"), ("(self)", "This firewall")]
        addresses += [(a.name, a.name + " · alias") for a in Alias.objects.exclude(type="port")]
        for interface in LogicalInterface.objects.all():
            addresses += [(f"@{interface.name}:net", interface.name + " network"), (f"@{interface.name}:ip", interface.name + " address")]
        addresses += [(g.name, g.name + " group network") for g in InterfaceGroup.objects.all()]
        for name in ("source", "destination"): self.fields[name].widget.choices = addresses
        ports = [(a.name, a.name + " · port alias") for a in Alias.objects.filter(type="port")]
        for name in ("source_port", "destination_port"): self.fields[name].widget.choices = ports
    def clean(self):
        data = super().clean()
        count = len(data.get("interfaces", [])) + len(data.get("interface_groups", []))
        if not count and not data.get("floating"):
            raise forms.ValidationError("Choose interfaces/groups, or select floating for a global rule.")
        if data.get("floating") and count == 1:
            raise forms.ValidationError("OPNsense treats a single binding as an interface/group rule. For floating use no bindings (global) or multiple bindings.")
        for field in ("source", "destination"):
            values = (data.get(field) or "").split(",")
            if "any" in values and len(values) > 1: self.add_error(field, "Any cannot be combined with other addresses.")
        for field in ("source_port", "destination_port"):
            if "," in (data.get(field) or ""):
                self.add_error(field, "OPNsense accepts one port, range or port alias here. Use a port alias for multiple ports.")
        if count > 1: data["floating"] = True
        import ipaddress
        allowed = set(Alias.objects.exclude(type="port").values_list("name", flat=True)) | {"any", "(self)"}
        allowed |= set(InterfaceGroup.objects.values_list("name", flat=True))
        allowed |= {f"@{i.name}:{kind}" for i in LogicalInterface.objects.all() for kind in ("net", "ip")}
        for field in ("source", "destination"):
            for value in (data.get(field) or "").split(","):
                if not value or value in allowed: continue
                try: ipaddress.ip_network(value, strict=False)
                except ValueError: self.add_error(field, "Choose an existing alias/interface or enter a valid address/network.")
        return data
    def save(self, commit=True):
        self.instance.interface = None
        return super().save(commit)


class CredentialsForm(forms.Form):
    api_key = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False), help_text="Leave both fields empty to keep saved credentials.")
    api_secret = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    clear_credentials = forms.BooleanField(required=False, label="Remove saved UI credentials and use environment credentials")
    def clean(self):
        data = super().clean()
        if bool(data.get("api_key")) != bool(data.get("api_secret")):
            raise forms.ValidationError("Enter both the API key and secret.")
        if data.get("clear_credentials") and data.get("api_key"):
            raise forms.ValidationError("Choose either replacement credentials or removal.")
        return data


class ImportRulesForm(forms.Form):
    snapshot_id = forms.IntegerField(widget=forms.HiddenInput)
    rule_indices = forms.MultipleChoiceField(widget=forms.CheckboxSelectMultiple, label="Rules to import")
    scope = forms.ChoiceField(choices=Rule._meta.get_field("scope").choices, initial="selected")
    firewalls = forms.ModelMultipleChoiceField(queryset=Firewall.objects.all(), required=False, widget=MultiSelectWidget())
    def __init__(self, *args, snapshot, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["rule_indices"].choices = [(str(i), row.get("description") or f"Rule {i + 1}") for i, row in enumerate(snapshot.data["rules"])]
        self.fields["snapshot_id"].initial = snapshot.pk
        self.fields["firewalls"].initial = [snapshot.firewall_id]
    def clean(self):
        data = super().clean()
        if data.get("scope") == "selected" and not data.get("firewalls"):
            raise forms.ValidationError("Select at least one target firewall.")
        return data


class LineTokenWidget(TokenWidget):
    def format_value(self, value):
        return value.splitlines() if isinstance(value, str) else super().format_value(value)
    def value_from_datadict(self, data, files, name):
        value = super().value_from_datadict(data, files, name)
        return value.replace(",", "\n")


class AliasForm(forms.ModelForm):
    content = forms.CharField(widget=LineTokenWidget(tags=True), help_text="Search aliases, or type an address/network/port and press Enter for each entry.")
    class Meta:
        model = Alias
        fields = "__all__"
        widgets = {"firewalls": MultiSelectWidget()}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["content"].widget.choices = [(a.name, a.name) for a in Alias.objects.exclude(pk=self.instance.pk)]

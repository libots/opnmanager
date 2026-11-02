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

from .models import Rule, Alias, LogicalInterface, Firewall, InterfaceGroup, FirewallGroup, Category
from .choices import ICMP_TYPES, ICMP6_TYPES, PROTOCOLS, PORTS, protocol_choices


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


class SearchSelect(TokenWidget):
    allow_multiple_selected=False
    def value_from_datadict(self,data,files,name): return data.get(name,'')


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
        exclude = ["interface", "floating"]
        widgets = {key: MultiSelectWidget() for key in ("interfaces", "interface_groups", "origin_interfaces", "origin_interface_groups", "categories", "firewalls", "firewall_groups")}
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', '')
        super().__init__(*args, **kwargs)
        # The admin removes model fields for users with view permission only.
        if 'name' not in self.fields: return
        for field in self.fields.values():
            field.help_text = field.help_text.split(' Hold down')[0]
        for field,label in {'name':'Description','interfaces':'Interface (rule)','interface_groups':'Interface groups (rule)','origin_interfaces':'Interface (origin)','origin_interface_groups':'Interface groups (origin)','ip_version':'Version','source_not':'Invert source','destination_not':'Invert destination','icmp_types':'ICMP type','icmp6_types':'ICMPv6 type'}.items():self.fields[field].label=label
        if self.instance.interface_id and not self.is_bound:
            self.initial['interfaces'] = [interface.pk for interface in self.instance.bound_interfaces()]
        help_texts = {
            'enabled': 'Enable this rule on targeted firewalls when deployed.',
            'name': 'The human-readable description. A compact manager identity tag is appended automatically when deployed.',
            'categories': 'Labels used to organize and filter rules.',
            'interfaces': 'Choose logical interfaces mapped to your firewalls. Leave rule interfaces and groups empty to match all interfaces.',
            'interface_groups': 'Groups can be used alongside individual rule interfaces. Placement is determined from the total number of bindings.',
            'origin_interfaces': 'Optionally match the interface on which a packet was originally received. Empty means any origin.',
            'origin_interface_groups': 'Optionally match a group of origin interfaces. Origin bindings do not determine floating placement.',
            'interface_not': 'Match interfaces other than the selected rule interfaces or groups.',
            'quick': 'Stop processing further rules when this rule matches.',
            'action': 'Pass permits traffic, block silently drops it, and reject sends a rejection response.',
            'direction': 'Match traffic entering, leaving, or in either direction on the rule interfaces.',
            'ip_version': 'Select IPv4, IPv6, or both address families.',
            'source_not': 'Match addresses outside the selected sources.',
            'destination_not': 'Match addresses outside the selected destinations.',
            'source': 'Choose an alias, interface network/address, built-in option, or enter a host or network.',
            'destination': 'Choose an alias, interface network/address, built-in option, or enter a host or network.',
            'source_port': 'Choose a service or port alias, or enter one port or a range such as 5060-5070. Empty means any port.',
            'destination_port': 'Choose a service or port alias, or enter one port or a range such as 5060-5070. Empty means any port.',
            'log': 'Log packets matching this rule on the firewall.',
            'sequence': 'Rule order on the firewall; lower values are evaluated first.',
            'scope': 'All targets every enabled firewall, including new devices. Selected uses the firewalls and groups below.',
            'firewalls': 'Direct targets when Scope is Selected. Empty direct targets are allowed when a firewall group is selected.',
            'firewall_groups': 'Targets include enabled firewalls in these groups, including devices added later.',
        }
        for name, text in help_texts.items(): self.fields[name].help_text = text
        self.fields['interface_not'].label = 'Invert rule interfaces'
        for name, placeholder in {'interfaces':'Any (all interfaces)', 'interface_groups':'No interface groups',
                                  'origin_interfaces':'Any origin', 'origin_interface_groups':'No origin groups',
                                  'source_port':'Any port', 'destination_port':'Any port'}.items():
            widget = self.fields[name].widget
            getattr(widget, 'widget', widget).attrs['data-placeholder'] = placeholder
        self.fields['protocol'].help_text='Refresh interface inventory to load the complete protocol catalog from your OPNsense devices.'
        choices=protocol_choices()
        self.fields['protocol'].allowed={value for value,label in choices}
        self.fields['protocol'].widget.choices=choices
        for name in ('action','direction','ip_version'):
            old=self.fields[name].widget.choices
            self.fields[name].widget=SearchSelect(choices=old)
        addresses = [("any", "Any"), ("(self)", "This firewall"),('bogons','Bogons'),('bogonsv6','Bogons IPv6')]
        addresses += [(a.name, a.name + " · alias") for a in Alias.objects.exclude(type="port")]
        for interface in LogicalInterface.objects.all():
            addresses += [(f"@{interface.name}:net", interface.name + " network"), (f"@{interface.name}:ip", interface.name + " address")]
        addresses += [(g.name, g.name + " group network") for g in InterfaceGroup.objects.all()]
        for name in ("source", "destination"): self.fields[name].widget.choices = addresses
        ports = [("", "Any")]+PORTS+[(a.name, a.name + " · port alias") for a in Alias.objects.filter(type="port")]
        for name in ("source_port", "destination_port"): self.fields[name].widget.choices = ports
    def clean(self):
        data = super().clean()
        count = len(data.get("interfaces", [])) + len(data.get("interface_groups", []))
        self.instance.floating = count != 1
        for field in ("source", "destination"):
            values = (data.get(field) or "").split(",")
            if "any" in values and len(values) > 1: self.add_error(field, "Any cannot be combined with other addresses.")
        for field in ("source_port", "destination_port"):
            if data.get(field)=="any":data[field]=""
            if "," in (data.get(field) or ""):
                self.add_error(field, "OPNsense accepts one port, range or port alias here. Use a port alias for multiple ports.")
        import ipaddress
        allowed = set(Alias.objects.exclude(type="port").values_list("name", flat=True)) | {"any", "(self)", "bogons", "bogonsv6"}
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
    firewall_groups = forms.ModelMultipleChoiceField(queryset=FirewallGroup.objects.all(), required=False, widget=MultiSelectWidget())
    def __init__(self, *args, snapshot, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["rule_indices"].choices = [(str(i), row.get("description") or f"Rule {i + 1}") for i, row in enumerate(snapshot.data["rules"])]
        self.fields["snapshot_id"].initial = snapshot.pk
        self.fields["firewalls"].initial = [snapshot.firewall_id]
    def clean(self):
        data = super().clean()
        if data.get("scope") == "selected" and not data.get("firewalls") and not data.get("firewall_groups"):
            raise forms.ValidationError("Select at least one firewall or firewall group.")
        return data


class LineTokenWidget(TokenWidget):
    def format_value(self, value):
        return value.splitlines() if isinstance(value, str) else super().format_value(value)
    def value_from_datadict(self, data, files, name):
        value = super().value_from_datadict(data, files, name)
        return value.replace(",", "\n")


class AliasForm(forms.ModelForm):
    expansion_preview = forms.CharField(required=False, disabled=True, widget=forms.Textarea(attrs={"rows": 6}), help_text="Saved-content preview (first 50 entries). The synchronization review shows the full payload.")
    content = forms.CharField(widget=LineTokenWidget(tags=True), help_text="Search aliases or type addresses, CIDRs, IP wildcard/range patterns, or ports. Edit as text accepts one item per line. Maximum 4096 compiled entries.")
    class Meta:
        model = Alias
        fields = "__all__"
        widgets = {"firewalls": MultiSelectWidget(), "firewall_groups": MultiSelectWidget()}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["content"].widget.choices = [(a.name, a.name) for a in Alias.objects.exclude(pk=self.instance.pk)]
        if self.instance.pk:
            from .alias_patterns import compile_content
            try:
                compiled = compile_content(self.instance.content, self.instance.type, Alias.objects.values_list("name", flat=True))
                entries = compiled.splitlines()
                self.initial["expansion_preview"] = f"{len(entries)} entries\n" + "\n".join(entries[:50])
            except ValueError as exc: self.initial["expansion_preview"] = str(exc)
    def clean(self):
        data = super().clean()
        if data.get("content") and data.get("type"):
            from .alias_patterns import compile_content
            try: compile_content(data["content"], data["type"], set(Alias.objects.values_list("name", flat=True)) | {data.get("name", "")})
            except ValueError as exc: self.add_error("content", str(exc))
        return data


class FirewallGroupForm(forms.ModelForm):
    class Meta:
        model = FirewallGroup
        fields = "__all__"
        widgets = {"firewalls": MultiSelectWidget()}


class HexColorWidget(forms.TextInput):
    input_type='color'
    def format_value(self,value): return '#'+str(value or '137b66').lstrip('#')
    def value_from_datadict(self,data,files,name): return data.get(name,'').lstrip('#')


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = "__all__"
        widgets = {"color": HexColorWidget(),"firewalls": MultiSelectWidget(), "firewall_groups": MultiSelectWidget()}


class InterfaceGroupForm(forms.ModelForm):
    class Meta:
        model = InterfaceGroup
        fields = "__all__"
        widgets = {key: MultiSelectWidget() for key in ("firewalls", "firewall_groups", "members")}

from .models import AuthenticationServer, FirewallAdministration, DNSProfile, VirtualIP

class AuthenticationServerForm(forms.ModelForm):
    secret=forms.CharField(required=False,widget=forms.PasswordInput(render_value=False),help_text='Optional replacement bind/shared secret. Empty keeps the saved value.')
    class Meta:
        model=AuthenticationServer
        fields='__all__'
        widgets={key:MultiSelectWidget() for key in ('firewalls','firewall_groups')}
    def save(self,commit=True):
        from .credentials import cipher
        obj=super().save(commit=False)
        if self.cleaned_data.get('secret'):obj.encrypted_secret=cipher().encrypt(self.cleaned_data['secret'].encode()).decode()
        if commit:obj.save();self.save_m2m()
        return obj

class AdministrationForm(forms.ModelForm):
    class Meta:
        model=FirewallAdministration
        fields='__all__'
        widgets={key:MultiSelectWidget() for key in ('authentication_servers','firewalls','firewall_groups')}

class DNSProfileForm(forms.ModelForm):
    class Meta:
        model=DNSProfile
        fields='__all__'
        widgets={key:MultiSelectWidget() for key in ('firewalls','firewall_groups')}

class VirtualIPForm(forms.ModelForm):
    class Meta:
        model=VirtualIP
        fields='__all__'
        widgets={key:MultiSelectWidget() for key in ('firewalls','firewall_groups')}

class OIDCSettingsForm(forms.Form):
    enabled=forms.BooleanField(required=False,label='Enable OIDC after server restart')
    issuer=forms.URLField(required=False)
    client_id=forms.CharField(required=False)
    client_secret=forms.CharField(required=False,widget=forms.PasswordInput(render_value=False),help_text='Empty retains the saved secret. Stored encrypted.')
    authorization_endpoint=forms.URLField(required=False)
    token_endpoint=forms.URLField(required=False)
    user_endpoint=forms.URLField(required=False)
    jwks_endpoint=forms.URLField(required=False)
    def clean(self):
        data=super().clean()
        if data.get('enabled'):
            for field in ('issuer','client_id','authorization_endpoint','token_endpoint','user_endpoint','jwks_endpoint'):
                if not data.get(field):self.add_error(field,'Required when OIDC is enabled.')
        for field in ('issuer','authorization_endpoint','token_endpoint','user_endpoint','jwks_endpoint'):
            if data.get(field):
                from urllib.parse import urlsplit
                url=urlsplit(data[field])
                if url.scheme!='https' or url.username or url.password:self.add_error(field,'Use an HTTPS URL without embedded credentials.')
        return data

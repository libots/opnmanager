import json

from django import forms

from .choices import ICMP6_TYPES, ICMP_TYPES, PORTS, protocol_choices
from .models import (
    Alias,
    AuthenticationServer,
    Category,
    DNSProfile,
    Firewall,
    FirewallAdministration,
    FirewallGroup,
    InterfaceGroup,
    LogicalInterface,
    Rule,
    VirtualIP,
)
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
            raise forms.ValidationError("Invalid snapshot JSON: " + str(exc)) from exc


class TokenWidget(forms.SelectMultiple):
    """Searchable select. `selector` picks the client-side control (static/opn-select.js):

    picker: OPNsense selectpicker look (default without tags); tags: free-form chips (alias content);
    net: networks with a "Single host or Network" manual entry; port: ports with a "Single port or range"
    manual entry; manual: a list plus one typed value (gateways).
    """

    def __init__(self, *args, tags=False, selector=None, **kwargs):
        attrs = kwargs.pop("attrs", {})
        attrs.update(
            {
                "class": "opn-select",
                "data-tags": "true" if tags else "false",
                "data-selector": selector or ("tags" if tags else "picker"),
            }
        )
        super().__init__(*args, attrs=attrs, **kwargs)

    def format_value(self, value):
        return (
            [v.strip() for v in value.split(",") if v.strip()]
            if isinstance(value, str)
            else super().format_value(value)
        )

    def value_from_datadict(self, data, files, name):
        values = super().value_from_datadict(data, files, name) or []
        if isinstance(values, str):
            values = values.split(",")
        return ",".join(dict.fromkeys(v.strip() for v in values if v.strip()))

    def optgroups(self, name, value, attrs=None):
        choices = list(self.choices)
        known = set()
        for key, label in choices:
            # Grouped choices are (group label, [(value, label), ...]).
            known.update(str(k) for k, _ in label) if isinstance(label, (list, tuple)) else known.add(str(key))
        self.choices = choices + [(v, v) for v in value if v not in known]
        try:
            groups = super().optgroups(name, value, attrs)
        finally:
            self.choices = choices
        # Saved values that aren't in the list were typed in; the picker shows them in its manual-entry box.
        for _, options, _ in groups:
            for option in options:
                if str(option["value"]) not in known:
                    option["attrs"]["data-manual"] = "true"
        return groups

    class Media:
        css = {"all": ["admin/css/vendor/select2/select2.css"]}
        js = [
            "admin/js/vendor/jquery/jquery.js",
            "admin/js/vendor/select2/select2.full.js",
            "admin/js/jquery.init.js",
            "selections.js",
            "opn-select.js",
        ]


class SearchSelect(TokenWidget):
    allow_multiple_selected = False

    def value_from_datadict(self, data, files, name):
        value = data.get(name, "")
        # A plain dict may carry a list; join it so validation can reject several values.
        return ",".join(value) if isinstance(value, (list, tuple)) else value

    def format_value(self, value):
        return [value] if isinstance(value, str) else super().format_value(value)


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


def binding_choices():
    """Interface (rule/origin) options in OPNsense's order: groups, then interfaces."""
    groups = [(f"group:{g.pk}", g.name) for g in InterfaceGroup.objects.order_by("name")]
    interfaces = [(f"interface:{i.pk}", i.name) for i in LogicalInterface.objects.order_by("name")]
    return [("Groups", groups), ("Interfaces", interfaces)]


def port_is_valid(value, aliases):
    """OPNsense PortField: a well-known name, a port alias, 1-65535, or a from-to range."""
    if value in aliases or value in dict(PORTS):
        return True
    if value.isdigit():
        return 1 <= int(value) <= 65535
    low, sep, high = value.partition("-")
    return bool(sep) and low.isdigit() and high.isdigit() and 1 <= int(low) < int(high) <= 65535


class RuleForm(forms.ModelForm):
    """Manager rule editor laid out like OPNsense's Firewall: Rules dialog.

    Field order, labels, which fields take several values and which are
    advanced-only follow OPNsense's dialogFilterRule.xml. Logical interfaces and
    interface groups are picked in one "Interface" list, as on the firewall.
    """

    # OPNsense hides these unless "advanced mode" is on.
    ADVANCED = ("interface_not", "origin_not")

    bindings = forms.MultipleChoiceField(required=False, label="Interface (rule)", widget=MultiSelectWidget())
    origin_bindings = forms.MultipleChoiceField(required=False, label="Interface (origin)", widget=MultiSelectWidget())
    protocol = forms.CharField(initial="any", widget=SearchSelect())
    source = CSVChoicesField(tags=True, initial="any")
    destination = CSVChoicesField(tags=True, initial="any")
    source_port = forms.CharField(required=False, widget=SearchSelect(tags=True, selector="port"))
    destination_port = forms.CharField(required=False, widget=SearchSelect(tags=True, selector="port"))
    gateway = forms.CharField(required=False, widget=SearchSelect(tags=True, selector="manual"))
    icmp_types = CSVChoicesField(choices=ICMP_TYPES, required=False)
    icmp6_types = CSVChoicesField(choices=ICMP6_TYPES, required=False)

    class Meta:
        model = Rule
        exclude = [
            "interface",
            "floating",
            "interfaces",
            "interface_groups",
            "origin_interfaces",
            "origin_interface_groups",
        ]
        widgets = {key: MultiSelectWidget() for key in ("categories", "firewalls", "firewall_groups")}

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("label_suffix", "")
        super().__init__(*args, **kwargs)
        # The admin removes model fields for users with view permission only.
        if "name" not in self.fields:
            return
        for field in self.fields.values():
            field.help_text = field.help_text.split(" Hold down")[0]
        labels = {
            "name": "Description",
            "interface_not": "Invert interface (rule)",
            "origin_not": "Invert interface (origin)",
            "ip_version": "Version",
            "source_not": "Invert Source",
            "source_port": "Source Port",
            "destination_not": "Invert Destination",
            "destination_port": "Destination Port",
            "icmp_types": "ICMP type",
            "icmp6_types": "ICMPv6 type",
            "state_type": "State type",
        }
        for name, label in labels.items():
            self.fields[name].label = label
        # Help texts are OPNsense's own; fields OPNsense documents without help keep none.
        help_texts = {
            "enabled": "Enable this rule",
            "sequence": "The order in which rules are being processed. Lower values are evaluated first. "
            "Each rule needs its own sequence on an interface.",
            "categories": "For grouping purposes you may select multiple groups here to organize items.",
            "name": "You may enter a description here for your reference (not parsed). "
            "A short manager tag is appended when the rule is pushed.",
            "interface_not": "Match packets on all but the selected rule interface.",
            "bindings": "Only match packets on the selected rule interfaces or groups. Interfaces that aren't "
            "mapped on a firewall are left out when pushing to it. No selection makes a floating rule "
            "for all interfaces.",
            "origin_not": "Match packets that were not received on the selected interface.",
            "origin_bindings": "Only match packets that were initially received on the selected interfaces or "
            "groups. This is mostly relevant for out direction rules when creating a security zone ruleset.",
            "quick": "If a packet matches a rule specifying quick, then that rule is considered the last matching "
            "rule and the specified action is taken. When a rule does not have quick enabled, the last matching "
            "rule wins.",
            "action": "Choose what to do with packets that match the criteria specified below. Hint: the "
            "difference between block and reject is that with reject, a packet (TCP RST or ICMP port unreachable "
            "for UDP) is returned to the sender, whereas with block the packet is dropped silently. In either "
            "case, the original packet is discarded.",
            "direction": "Direction of the traffic. The default policy is to filter inbound traffic, which sets "
            "the policy to the interface originally receiving the traffic.",
            "ip_version": "",
            "protocol": "",
            "icmp_types": "",
            "icmp6_types": "",
            "source_not": "Use this option to invert the sense of the match.",
            "source": "",
            "source_port": "Source port number or well known name (imap, imaps, http, https, ...), "
            "for ranges use a dash",
            "destination_not": "Use this option to invert the sense of the match.",
            "destination": "",
            "destination_port": "Destination port number or well known name (imap, imaps, http, https, ...), "
            "for ranges use a dash",
            "log": "Log packets that are handled by this rule",
            "state_type": "State tracking mechanism to use, default is full stateful tracking, sloppy ignores "
            "sequence numbers, use none for stateless rules.",
            "gateway": "Leave as 'default' to use the system routing table. Or choose a gateway to utilize "
            "policy based routing. The name must exist on every firewall the rule is pushed to.",
            "scope": "All targets every enabled firewall, including new devices. Selected uses the firewalls "
            "and groups below.",
            "firewalls": "Direct targets when Scope is Selected.",
            "firewall_groups": "Targets include enabled firewalls in these groups, including devices added later.",
        }
        for name, text in help_texts.items():
            self.fields[name].help_text = text

        choices = binding_choices()
        for name in ("bindings", "origin_bindings"):
            self.fields[name].choices = choices
        self.fields["bindings"].widget.attrs["data-placeholder"] = "any"
        self.fields["origin_bindings"].widget.attrs["data-placeholder"] = "any"
        self.fields["categories"].widget.attrs["data-placeholder"] = "Nothing selected"
        if not self.instance._state.adding and not self.is_bound:
            rule = self.instance
            self.initial["bindings"] = [f"interface:{i.pk}" for i in rule.bound_interfaces()] + [
                f"group:{g.pk}" for g in rule.interface_groups.all()
            ]
            self.initial["origin_bindings"] = [f"interface:{i.pk}" for i in rule.origin_interfaces.all()] + [
                f"group:{g.pk}" for g in rule.origin_interface_groups.all()
            ]

        protocols = protocol_choices()
        self.fields["protocol"].widget.choices = protocols
        self._protocols = {value for value, label in protocols}
        # Rules saved before Protocol became single-valued keep their list until edited.
        if "," in (self.instance.protocol or ""):
            self.fields["protocol"].widget = TokenWidget(choices=protocols)
        for name in ("action", "direction", "ip_version", "state_type", "scope"):
            self.fields[name].widget = SearchSelect(choices=self.fields[name].widget.choices)
        self.fields["state_type"].required = False

        aliases = sorted(Alias.objects.exclude(type="port").values_list("name", flat=True), key=str.lower)
        networks = [("any", "any"), ("(self)", "This Firewall")]
        for interface in LogicalInterface.objects.order_by("name"):
            networks += [
                (f"@{interface.name}:net", f"{interface.name} network"),
                (f"@{interface.name}:ip", f"{interface.name} address"),
            ]
        networks += [(g.name, f"{g.name} network") for g in InterfaceGroup.objects.order_by("name")]
        networks += [("bogons", "bogons"), ("bogonsv6", "bogonsv6")]
        for name in ("source", "destination"):
            widget = self.fields[name].widget
            widget.choices = [("Aliases", [(a, a) for a in aliases]), ("Networks", networks)]
            widget.attrs["data-selector"] = "net"

        port_aliases = sorted(Alias.objects.filter(type="port").values_list("name", flat=True), key=str.lower)
        self._port_aliases = set(port_aliases)
        well_known = [(name, label.upper()) for name, label in PORTS]
        for name in ("source_port", "destination_port"):
            self.fields[name].widget.choices = [
                ("Aliases", [(a, a) for a in port_aliases]),
                ("Ports", [("", "any")] + well_known),
            ]
        self.fields["gateway"].widget.choices = [("", "default")] + [(g, g) for g in observed_gateways()]

    def advanced_has_values(self):
        """Advanced fields set away from their defaults; the editor opens in advanced mode then."""
        if self.is_bound:
            return any(self.data.get(name) for name in self.ADVANCED)
        return any(getattr(self.instance, name) for name in self.ADVANCED)

    def clean_protocol(self):
        value = self.cleaned_data["protocol"]
        values = [v for v in value.split(",") if v]
        legacy = "," in (self.instance.protocol or "")
        if len(values) != 1 and not (legacy and values):
            raise forms.ValidationError("Choose one protocol.")
        if any(v not in self._protocols for v in values):
            raise forms.ValidationError("Choose a supported protocol.")
        return value

    def clean(self):
        data = super().clean()
        for prefix in ("", "origin_"):
            chosen = data.get(prefix + "bindings") or []
            interface_ids = [int(v.split(":")[1]) for v in chosen if v.startswith("interface:")]
            group_ids = [int(v.split(":")[1]) for v in chosen if v.startswith("group:")]
            data[prefix + "interface_ids"], data[prefix + "group_ids"] = interface_ids, group_ids
        self.instance.floating = len(data["interface_ids"]) + len(data["group_ids"]) != 1
        data["state_type"] = data.get("state_type") or "keep"
        for field in ("source", "destination"):
            values = (data.get(field) or "").split(",")
            if "any" in values and len(values) > 1:
                self.add_error(field, "Any cannot be combined with other addresses.")
        for field in ("source_port", "destination_port"):
            value = data.get(field) or ""
            if value == "any":
                data[field] = value = ""
            if "," in value:
                self.add_error(
                    field, "OPNsense accepts one port, range or port alias here. Use a port alias for multiple ports."
                )
            elif value and not port_is_valid(value, self._port_aliases):
                self.add_error(field, "Please specify a valid portnumber, name, alias or range.")
        import ipaddress

        allowed = set(Alias.objects.exclude(type="port").values_list("name", flat=True)) | {
            "any",
            "(self)",
            "bogons",
            "bogonsv6",
        }
        allowed |= set(InterfaceGroup.objects.values_list("name", flat=True))
        allowed |= {f"@{i.name}:{kind}" for i in LogicalInterface.objects.all() for kind in ("net", "ip")}
        for field in ("source", "destination"):
            for value in (data.get(field) or "").split(","):
                if not value or value in allowed:
                    continue
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    self.add_error(field, "Choose an existing alias/interface or enter a valid address/network.")
        return data

    def save(self, commit=True):
        self.instance.interface = None
        return super().save(commit)

    def _save_m2m(self):
        super()._save_m2m()
        data = self.cleaned_data
        self.instance.interfaces.set(data["interface_ids"])
        self.instance.interface_groups.set(data["group_ids"])
        self.instance.origin_interfaces.set(data["origin_interface_ids"])
        self.instance.origin_interface_groups.set(data["origin_group_ids"])


def observed_gateways():
    """Gateway names already used by rules in each firewall's newest snapshot."""
    names = set()
    for firewall in Firewall.objects.all():
        snapshot = firewall.snapshots.first()
        rules = (snapshot.data or {}).get("rules", []) if snapshot else []
        names.update(row.get("gateway", "") for row in rules if isinstance(row, dict))
    names.discard("")
    return sorted(names, key=str.lower)


class CredentialsForm(forms.Form):
    api_key = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Leave both fields empty to keep saved credentials.",
    )
    api_secret = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    clear_credentials = forms.BooleanField(
        required=False, label="Remove saved UI credentials and use environment credentials"
    )

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
    firewalls = forms.ModelMultipleChoiceField(
        queryset=Firewall.objects.all(), required=False, widget=MultiSelectWidget()
    )
    firewall_groups = forms.ModelMultipleChoiceField(
        queryset=FirewallGroup.objects.all(), required=False, widget=MultiSelectWidget()
    )

    def __init__(self, *args, snapshot, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["rule_indices"].choices = [
            (str(i), row.get("description") or f"Rule {i + 1}") for i, row in enumerate(snapshot.data["rules"])
        ]
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
    expansion_preview = forms.CharField(
        required=False,
        disabled=True,
        widget=forms.Textarea(attrs={"rows": 6}),
        help_text="Saved-content preview (first 50 entries). The synchronization review shows the full payload.",
    )
    content = forms.CharField(
        widget=LineTokenWidget(tags=True),
        help_text="Search aliases or type addresses, CIDRs, IP wildcard/range patterns, or ports. Edit as text accepts one item per line. Maximum 4096 compiled entries.",
    )

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
                compiled = compile_content(
                    self.instance.content, self.instance.type, Alias.objects.values_list("name", flat=True)
                )
                entries = compiled.splitlines()
                self.initial["expansion_preview"] = f"{len(entries)} entries\n" + "\n".join(entries[:50])
            except ValueError as exc:
                self.initial["expansion_preview"] = str(exc)

    def clean(self):
        data = super().clean()
        if data.get("content") and data.get("type"):
            from .alias_patterns import compile_content

            try:
                compile_content(
                    data["content"],
                    data["type"],
                    set(Alias.objects.values_list("name", flat=True)) | {data.get("name", "")},
                )
            except ValueError as exc:
                self.add_error("content", str(exc))
        return data


class FirewallGroupForm(forms.ModelForm):
    class Meta:
        model = FirewallGroup
        fields = "__all__"
        widgets = {"firewalls": MultiSelectWidget()}


class HexColorWidget(forms.TextInput):
    input_type = "color"

    def format_value(self, value):
        return "#" + str(value or "137b66").lstrip("#")

    def value_from_datadict(self, data, files, name):
        return data.get(name, "").lstrip("#")


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = "__all__"
        widgets = {"color": HexColorWidget(), "firewalls": MultiSelectWidget(), "firewall_groups": MultiSelectWidget()}


class InterfaceGroupForm(forms.ModelForm):
    class Meta:
        model = InterfaceGroup
        fields = "__all__"
        widgets = {key: MultiSelectWidget() for key in ("firewalls", "firewall_groups", "members")}


class AuthenticationServerForm(forms.ModelForm):
    secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Optional replacement bind/shared secret. Empty keeps the saved value.",
    )

    class Meta:
        model = AuthenticationServer
        fields = "__all__"
        widgets = {key: MultiSelectWidget() for key in ("firewalls", "firewall_groups")}

    def save(self, commit=True):
        from .credentials import cipher

        obj = super().save(commit=False)
        if self.cleaned_data.get("secret"):
            obj.encrypted_secret = cipher().encrypt(self.cleaned_data["secret"].encode()).decode()
        if commit:
            obj.save()
            self.save_m2m()
        return obj


class AdministrationForm(forms.ModelForm):
    class Meta:
        model = FirewallAdministration
        fields = "__all__"
        widgets = {key: MultiSelectWidget() for key in ("authentication_servers", "firewalls", "firewall_groups")}


class DNSProfileForm(forms.ModelForm):
    class Meta:
        model = DNSProfile
        fields = "__all__"
        widgets = {key: MultiSelectWidget() for key in ("firewalls", "firewall_groups")}


class VirtualIPForm(forms.ModelForm):
    class Meta:
        model = VirtualIP
        fields = "__all__"
        widgets = {key: MultiSelectWidget() for key in ("firewalls", "firewall_groups")}


class OIDCSettingsForm(forms.Form):
    enabled = forms.BooleanField(required=False, label="Enable OIDC after server restart")
    issuer = forms.URLField(required=False)
    client_id = forms.CharField(required=False)
    client_secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Empty retains the saved secret. Stored encrypted.",
    )
    authorization_endpoint = forms.URLField(required=False)
    token_endpoint = forms.URLField(required=False)
    user_endpoint = forms.URLField(required=False)
    jwks_endpoint = forms.URLField(required=False)

    def clean(self):
        data = super().clean()
        if data.get("enabled"):
            for field in (
                "issuer",
                "client_id",
                "authorization_endpoint",
                "token_endpoint",
                "user_endpoint",
                "jwks_endpoint",
            ):
                if not data.get(field):
                    self.add_error(field, "Required when OIDC is enabled.")
        for field in ("issuer", "authorization_endpoint", "token_endpoint", "user_endpoint", "jwks_endpoint"):
            if data.get(field):
                from urllib.parse import urlsplit

                url = urlsplit(data[field])
                if url.scheme != "https" or url.username or url.password:
                    self.add_error(field, "Use an HTTPS URL without embedded credentials.")
        return data


def rule_form_data(rule):
    """A saved rule as the POST data its editor would submit, for re-validating partial edits."""
    from django.utils.datastructures import MultiValueDict

    data = MultiValueDict()
    for field in RuleForm(instance=rule):
        widget, value = field.field.widget, field.value()
        if isinstance(widget, forms.CheckboxInput):
            if value:
                data[field.name] = "on"
        elif isinstance(widget, forms.SelectMultiple):
            data.setlist(field.name, [str(v) for v in widget.format_value(value) if v not in (None, "")])
        else:
            data[field.name] = "" if value is None else str(value)
    return data


def comparable(data, name):
    """One field's submitted value in a form that compares equal across rules."""
    values = data.getlist(name)
    return tuple(sorted(values)) if len(values) > 1 else (values[0] if values else "")


def bulk_rule_forms(rules, posted, changed):
    """Re-validate each rule with only the fields in `changed` taken from `posted`."""
    forms_ = []
    for rule in rules:
        data = rule_form_data(rule)
        for name in changed:
            values = posted.getlist(name)
            if values:
                data.setlist(name, values)
            else:
                data.pop(name, None)
        forms_.append(RuleForm(data, instance=rule))
    return forms_

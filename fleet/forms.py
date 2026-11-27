import json

from django import forms

from .choices import ICMP6_TYPES, ICMP_TYPES, PORTS, protocol_choices
from .models import (
    Alias,
    Category,
    DhcpScope,
    DNSProfile,
    Firewall,
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

    picker: OPNsense selectpicker look (default without tags); tags: free-form chips like OPNsense's
    tokenizer (alias content);
    net: networks with a "Single host or Network" manual entry; port: ports with a "Single port or range"
    manual entry; manual: a list plus one typed value (gateways).
    """

    def __init__(self, *args, tags=False, selector=None, option_attrs=None, **kwargs):
        # Per-option attributes, e.g. {"https": {"data-hint": "443", "data-only": "port"}}: tags show
        # data-hint next to a suggestion and offer data-only options only for matching data-filter-by values.
        self.option_attrs = option_attrs or {}
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
        if self.attrs.get("data-selector") == "tags":
            # Chips show in option order: keep the saved order rather than listing known names first.
            labels = dict(self.choices)
            self.choices = [(v, labels[v]) for v in value] + [(k, label) for k, label in choices if k not in value]
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

    def create_option(self, name, value, label, selected, index, subindex=None, attrs=None):
        option = super().create_option(name, value, label, selected, index, subindex, attrs)
        option["attrs"].update(self.option_attrs.get(str(value), {}))
        return option

    class Media:
        js = ["opn-select.js"]


def suggestion_field(label, help_text, choices, option_attrs=None, **attrs):
    """A comma-separated CharField edited as ordered, free-form chips with suggestions."""
    widget = TokenWidget(choices=choices, tags=True, option_attrs=option_attrs, attrs=attrs)
    return forms.CharField(label=label, required=False, help_text=help_text, widget=widget)


def server_suggestions(include_router=True):
    """Choices and hints for DNS/NTP/gateway server lists: the firewall itself and host aliases."""
    choices, hints = [], {}
    if include_router:
        choices.append(("0.0.0.0", "0.0.0.0"))
        hints["0.0.0.0"] = {"data-hint": "this firewall on the interface"}
    for alias in Alias.objects.filter(type="host"):
        choices.append((alias.name, alias.name))
        members = [m.strip() for m in alias.content.splitlines() if m.strip()]
        hints[alias.name] = {"data-hint": "alias: " + ", ".join(members[:3]) + (" …" if len(members) > 3 else "")}
    return choices, hints


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
    interfaces = [(f"interface:{i.pk}", i.name) for i in LogicalInterface.objects.all()]
    return [("Groups", groups), ("Interfaces", interfaces)]


def port_is_valid(value, aliases):
    """OPNsense PortField: a well-known name, a port alias, 1-65535, or a from-to range."""
    if value in aliases or value in dict(PORTS):
        return True
    if value.isdigit():
        return 1 <= int(value) <= 65535
    low, sep, high = value.partition("-")
    return bool(sep) and low.isdigit() and high.isdigit() and 1 <= int(low) < int(high) <= 65535


ALL_TARGETS = "all"


def target_choices():
    """ "Deploy to" options: everything, then firewall groups, then single firewalls."""
    return [
        (ALL_TARGETS, "All enabled firewalls"),
        ("Firewall groups", [(f"group:{g.pk}", g.name) for g in FirewallGroup.objects.order_by("name")]),
        ("Firewalls", [(f"firewall:{f.pk}", f.name) for f in Firewall.objects.all()]),
    ]


TARGETS_HELP = (
    "All enabled firewalls includes devices added later. Otherwise pick firewall groups and single "
    "firewalls; a group also covers firewalls added to it later. Nothing selected targets no firewall."
)


def targets_field():
    widget = MultiSelectWidget(attrs={"data-exclusive": ALL_TARGETS, "data-placeholder": "Nothing selected"})
    return forms.MultipleChoiceField(required=False, label="Deploy to", widget=widget, help_text=TARGETS_HELP)


def split_targets(values):
    """(scope, firewall ids, firewall group ids) from "Deploy to" values."""
    values = list(values or [])
    if ALL_TARGETS in values:
        return ALL_TARGETS, [], []
    firewalls = [int(v.split(":", 1)[1]) for v in values if v.startswith("firewall:")]
    groups = [int(v.split(":", 1)[1]) for v in values if v.startswith("group:")]
    return "selected", firewalls, groups


def with_legacy_targets(data):
    """Form data with "targets" derived from the former scope / firewalls / firewall_groups fields.

    Lets API clients and saved links that still post the three fields keep working.
    """
    if "targets" in data or "scope" not in data:
        return data
    getlist = data.getlist if hasattr(data, "getlist") else lambda key: data.get(key) or []
    if data.get("scope") == ALL_TARGETS:
        targets = [ALL_TARGETS]
    else:
        targets = [f"firewall:{pk}" for pk in getlist("firewalls")] + [
            f"group:{pk}" for pk in getlist("firewall_groups")
        ]
    data = data.copy()
    if hasattr(data, "setlist"):
        data.setlist("targets", targets)
    else:
        data["targets"] = targets
    return data


class TargetsFormMixin:
    """One "Deploy to" picker in place of Scope, Firewalls and Firewall groups.

    It works like Source in the rule editor: "All enabled firewalls" stands alone,
    otherwise any mix of firewall groups and firewalls. Posts that still send the
    three separate fields are understood too.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            # Django's "Hold down Control" hint is for native multi-selects; pickers toggle on click.
            field.help_text = str(field.help_text).split(" Hold down")[0]
        if "targets" not in self.fields:
            return
        self.fields["targets"].choices = target_choices()
        if self.is_bound:
            self.data = with_legacy_targets(self.data)
        instance = getattr(self, "instance", None)
        if instance is not None and not instance._state.adding:
            self.initial.setdefault(
                "targets",
                [ALL_TARGETS]
                if instance.scope == ALL_TARGETS
                else [f"group:{g.pk}" for g in instance.firewall_groups.all()]
                + [f"firewall:{f.pk}" for f in instance.firewalls.all()],
            )
        else:
            self.initial.setdefault("targets", [ALL_TARGETS])

    def clean_targets(self):
        values = self.cleaned_data.get("targets") or []
        if ALL_TARGETS in values and len(values) > 1:
            raise forms.ValidationError("All enabled firewalls can't be combined with groups or firewalls.")
        return values

    def save(self, commit=True):
        # self.errors runs validation when save() is called without is_valid().
        if "targets" in self.fields and not self.errors:
            self.instance.scope = split_targets(self.cleaned_data.get("targets"))[0]
        return super().save(commit)

    def _save_m2m(self):
        super()._save_m2m()
        if "targets" in self.fields:
            _, firewalls, groups = split_targets(self.cleaned_data.get("targets"))
            self.instance.firewalls.set(firewalls)
            self.instance.firewall_groups.set(groups)


SCOPE_FIELDS = ["scope", "firewalls", "firewall_groups"]


class RuleForm(TargetsFormMixin, forms.ModelForm):
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
    targets = targets_field()

    class Meta:
        model = Rule
        exclude = [
            *SCOPE_FIELDS,
            "floating",
            "interfaces",
            "interface_groups",
            "origin_interfaces",
            "origin_interface_groups",
        ]
        widgets = {"categories": MultiSelectWidget()}

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
            "targets": TARGETS_HELP,
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
        for name in ("action", "direction", "ip_version", "state_type"):
            self.fields[name].widget = SearchSelect(choices=self.fields[name].widget.choices)
        self.fields["state_type"].required = False

        aliases = sorted(Alias.objects.exclude(type="port").values_list("name", flat=True), key=str.lower)
        networks = [("any", "any"), ("(self)", "This Firewall")]
        for interface in LogicalInterface.objects.all():
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
    targets = targets_field()

    def __init__(self, *args, snapshot, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["rule_indices"].choices = [
            (str(i), row.get("description") or f"Rule {i + 1}") for i, row in enumerate(snapshot.data["rules"])
        ]
        self.fields["snapshot_id"].initial = snapshot.pk
        self.fields["targets"].choices = target_choices()
        self.fields["targets"].initial = [f"firewall:{snapshot.firewall_id}"]
        if self.is_bound:
            self.data = with_legacy_targets(self.data)

    def clean(self):
        data = super().clean()
        targets = data.get("targets") or []
        if not targets:
            raise forms.ValidationError("Select at least one firewall or firewall group.")
        if ALL_TARGETS in targets and len(targets) > 1:
            raise forms.ValidationError("All enabled firewalls can't be combined with groups or firewalls.")
        scope, firewalls, groups = split_targets(targets)
        data["scope"] = scope
        data["firewalls"] = Firewall.objects.filter(pk__in=firewalls)
        data["firewall_groups"] = FirewallGroup.objects.filter(pk__in=groups)
        return data


class LineTokenWidget(TokenWidget):
    def format_value(self, value):
        return value.splitlines() if isinstance(value, str) else super().format_value(value)

    def value_from_datadict(self, data, files, name):
        value = super().value_from_datadict(data, files, name)
        return value.replace(",", "\n")


class AliasForm(TargetsFormMixin, forms.ModelForm):
    expansion_preview = forms.CharField(
        required=False,
        disabled=True,
        widget=forms.Textarea(attrs={"rows": 6}),
        help_text="Saved-content preview (first 50 entries). The synchronization review shows the full payload.",
    )
    content = forms.CharField(
        widget=LineTokenWidget(tags=True),
        help_text="Search aliases or type addresses, CIDRs, IP wildcard/range patterns, or ports. Text switches to one item per line. Maximum 4096 compiled entries.",
    )

    targets = targets_field()

    class Meta:
        model = Alias
        exclude = SCOPE_FIELDS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        widget = self.fields["content"].widget
        aliases = list(Alias.objects.exclude(pk=self.instance.pk))
        widget.choices = [(a.name, a.name) for a in aliases] + [(name, name) for name, _ in PORTS]
        widget.option_attrs = {
            **{a.name: {"data-hint": f"{a.get_type_display()} alias"} for a in aliases},
            **{name: {"data-hint": label.rpartition("(")[2].rstrip(")"), "data-only": "port"} for name, label in PORTS},
        }
        widget.attrs["data-filter-by"] = "type"
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


class CategoryForm(TargetsFormMixin, forms.ModelForm):
    targets = targets_field()

    class Meta:
        model = Category
        exclude = SCOPE_FIELDS
        widgets = {"color": HexColorWidget()}


class InterfaceGroupForm(TargetsFormMixin, forms.ModelForm):
    targets = targets_field()

    class Meta:
        model = InterfaceGroup
        # OPNsense's Firewall: Groups dialog order.
        fields = ["name", "members", "sequence", "no_gui_group", "description"]
        widgets = {"members": MultiSelectWidget()}


class DNSProfileForm(TargetsFormMixin, forms.ModelForm):
    targets = targets_field()

    class Meta:
        model = DNSProfile
        exclude = SCOPE_FIELDS


class VirtualIPForm(TargetsFormMixin, forms.ModelForm):
    targets = targets_field()

    class Meta:
        model = VirtualIP
        exclude = SCOPE_FIELDS


def check_server_list(value, field_label, aliases):
    """Syntax of a DHCP server list: 0.0.0.0, templates, +N/-N offsets or host alias names."""
    import re

    from .ipam import RELATIVE, ROUTER, TemplateError, check_template

    problems = []
    for token in [t.strip() for t in re.split(r"[,\s]+", value or "") if t.strip()]:
        if token == ROUTER or RELATIVE.match(token) or token in aliases:
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            problems.append(f"{token} is not a host alias")
            continue
        try:
            if check_template(token) != 4:
                problems.append(f"{token} is not IPv4")
        except TemplateError as exc:
            problems.append(str(exc))
    if problems:
        raise forms.ValidationError(f"{field_label}: " + "; ".join(problems) + ".")
    return ", ".join(t.strip() for t in re.split(r"[,\s]+", value or "") if t.strip())


class DhcpScopeForm(TargetsFormMixin, forms.ModelForm):
    targets = targets_field()

    class Meta:
        model = DhcpScope
        exclude = SCOPE_FIELDS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices, hints = server_suggestions()
        for name in ("gateway", "ntp_servers"):
            self.fields[name].widget = TokenWidget(choices=choices, tags=True, option_attrs=hints)
        choices, hints = dns_list_suggestions("servers", with_lists=True)
        self.fields["dns_servers"].widget = TokenWidget(
            choices=choices, tags=True, option_attrs=hints, attrs={"data-separators": "comma"}
        )

    def clean(self):
        data = super().clean()
        aliases = set(Alias.objects.filter(type="host").values_list("name", flat=True))
        for field in ("gateway", "ntp_servers"):
            if data.get(field):
                try:
                    data[field] = check_server_list(data[field], self.fields[field].label, aliases)
                except forms.ValidationError as exc:
                    self.add_error(field, exc)
        if data.get("dns_servers"):
            from .ipam import check_preference, preference_tokens
            from .models import dns_bases, dns_lists

            host_aliases = {a.name: a.content for a in Alias.objects.filter(type="host")}
            names = set(Firewall.objects.values_list("name", flat=True))
            problems = check_preference(
                data["dns_servers"], "servers", names, host_aliases, dns_bases(), set(dns_lists())
            )
            if problems:
                self.add_error("dns_servers", "DNS servers: " + "; ".join(problems) + ".")
            else:
                data["dns_servers"] = ", ".join(preference_tokens(data["dns_servers"]))
        return data


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


def rule_form_initial(data, names):
    """Editor initial values for `names` from submitted-style data (see rule_form_data).

    Single-value pickers (protocol, ports, gateway...) need a string: an empty list
    would leave nothing selected, and the picker would fall back to its first option.
    """
    initial = {}
    for name, field in RuleForm().fields.items():
        if name not in names:
            continue
        widget = field.widget
        if isinstance(widget, forms.CheckboxInput):
            initial[name] = name in data
        elif isinstance(widget, SearchSelect):
            initial[name] = ",".join(data.getlist(name))
        elif isinstance(widget, forms.SelectMultiple):
            initial[name] = data.getlist(name)
        elif name in data:
            initial[name] = data[name]
    return initial


def dns_list_suggestions(kind, with_lists=False, exclude=None):
    """Suggestions for a DNS list: other preference lists (list:<name>), router, each base as
    base / this. / others. / <site>., and host aliases (servers), each with a hint."""
    from .models import DnsBase, DnsPreference

    wanted = "servers" if kind == "servers" else "domains"
    choices, hints = [], {}

    def offer(value, hint):
        choices.append((value, value))
        hints[value] = {"data-hint": hint}

    if with_lists:
        for preference in DnsPreference.objects.exclude(pk=exclude):
            field = preference.dns_servers if kind == "servers" else preference.search_domains
            offer(
                f"list:{preference.name}",
                ("default list: " if preference.is_default else "list: ") + (field or "empty"),
            )

    if kind == "servers":
        offer("router", "the firewall on the interface")
    sites = list(Firewall.objects.all())
    for base in DnsBase.objects.filter(kind=wanted):
        offer(f"this.{base.name}", f"this site's {base.name}")
        offer(f"others.{base.name}", f"every other site's {base.name}")
        offer(base.name, f"this site's {base.name}, then the others'")
        for fw in sites:
            offer(f"{fw.name}.{base.name}", f"{fw.name}'s {base.name}")
    if kind == "servers":
        alias_choices, alias_hints = server_suggestions(include_router=False)
        choices += alias_choices
        hints.update(alias_hints)
    return choices, hints


class DnsPreferenceForm(forms.ModelForm):
    class Meta:
        from .models import DnsPreference

        model = DnsPreference
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, kind in (("dns_servers", "servers"), ("search_domains", "search")):
            choices, hints = dns_list_suggestions(kind, with_lists=True, exclude=self.instance.pk)
            self.fields[name].widget = TokenWidget(
                choices=choices, tags=True, option_attrs=hints, attrs={"data-separators": "comma"}
            )


class DnsBaseForm(forms.ModelForm):
    class Meta:
        from .models import DnsBase

        model = DnsBase
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices, hints = server_suggestions(include_router=False)
        for value in hints:
            hints[value]["data-only"] = "servers"
        widget = TokenWidget(choices=choices, tags=True, option_attrs=hints, attrs={"data-filter-by": "kind"})
        self.fields["default"].widget = widget

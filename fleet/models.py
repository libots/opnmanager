import uuid
from urllib.parse import urlsplit

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxLengthValidator, MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models, transaction

identifier = RegexValidator(
    r"^[A-Za-z_][A-Za-z0-9_]*$", "Use letters, digits and underscores; start with a letter or underscore."
)


class FirewallGroup(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=255, blank=True)
    firewalls = models.ManyToManyField("Firewall", blank=True, related_name="groups")

    def __str__(self):
        return self.name

    class Meta:
        ordering = ["name"]


class Firewall(models.Model):
    name = models.CharField(max_length=100, unique=True)
    base_url = models.URLField(help_text="HTTPS management URL, e.g. https://fw.example.net")
    enabled = models.BooleanField(default=True)
    credential_prefix = models.CharField(
        max_length=80,
        blank=True,
        validators=[identifier],
        help_text="Environment variable prefix, e.g. BRANCH1; reads BRANCH1_API_KEY and BRANCH1_API_SECRET",
    )
    ca_bundle = models.CharField(
        max_length=500, blank=True, help_text="Optional PEM CA file path; TLS verification is always enabled."
    )
    notes = models.TextField(blank=True)
    auto_map_interfaces = models.BooleanField(
        default=True,
        help_text="Add missing mappings using unique interface display names when pulling a snapshot; preserve manual mappings.",
    )
    encrypted_api_key = models.TextField(blank=True, editable=False)
    encrypted_api_secret = models.TextField(blank=True, editable=False)

    def clean(self):
        url = urlsplit(self.base_url)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path not in ("", "/")
        ):
            raise ValidationError({"base_url": "Use an HTTPS origin without credentials, path, query or fragment."})

    def __str__(self):
        return self.name

    class Meta:
        ordering = ["name"]
        permissions = [
            ("refresh_firewall", "Can import and refresh firewall snapshots"),
            ("manage_credentials", "Can manage firewall API credentials"),
            ("sync_definitions", "Can synchronize aliases, categories and interface groups"),
            ("deploy_rules", "Can deploy selected firewall rules"),
        ]


class LogicalInterface(models.Model):
    name = models.CharField(max_length=50, unique=True, validators=[identifier])
    description = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        previous = None
        if self.pk:
            previous = LogicalInterface.objects.filter(pk=self.pk).values_list("name", flat=True).first()
        with transaction.atomic():
            super().save(*args, **kwargs)
            if previous and previous != self.name:
                # Bindings, groups and mappings follow the foreign key; addresses name it as text.
                for rule in Rule.objects.filter(
                    models.Q(source__contains=f"@{previous}:") | models.Q(destination__contains=f"@{previous}:")
                ):
                    changed = False
                    for field in ("source", "destination"):
                        value = getattr(rule, field)
                        for kind in ("net", "ip"):
                            value, _ = _replace_token(value, f"@{previous}:{kind}", f"@{self.name}:{kind}", ",")
                        if value != getattr(rule, field):
                            setattr(rule, field, value)
                            changed = True
                    if changed:
                        rule.save()

    class Meta:
        ordering = ["name"]


class InterfaceMapping(models.Model):
    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE, related_name="interface_mappings")
    logical_interface = models.ForeignKey(LogicalInterface, on_delete=models.PROTECT)
    device_interface = models.CharField(
        max_length=50, validators=[identifier], help_text="Local OPNsense identifier, e.g. opt2, not its display label."
    )

    def __str__(self):
        return f"{self.firewall}: {self.logical_interface} → {self.device_interface}"

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["firewall", "logical_interface"], name="one_logical_interface_per_firewall"
            ),
            models.UniqueConstraint(fields=["firewall", "device_interface"], name="one_device_interface_per_firewall"),
        ]


class ScopedPolicy(models.Model):
    ALL = "all"
    SELECTED = "selected"
    scope = models.CharField(
        max_length=10,
        choices=[(ALL, "All enabled firewalls"), (SELECTED, "Selected firewalls / firewall groups")],
        default=ALL,
    )
    firewalls = models.ManyToManyField(
        Firewall,
        blank=True,
        help_text="Used for Selected firewalls / firewall groups. Direct selections and group memberships are combined; an empty combined selection targets none.",
    )
    firewall_groups = models.ManyToManyField(
        FirewallGroup,
        blank=True,
        help_text="Combined with directly selected firewalls. Membership changes apply automatically.",
    )

    class Meta:
        abstract = True

    SCOPE_PREFETCH = ("firewalls", "firewall_groups__firewalls")

    def applies_to(self, firewall):
        if not firewall.enabled:
            return False
        if self.scope == self.ALL:
            return True
        cache = getattr(self, "_prefetched_objects_cache", {})
        if "firewalls" in cache and "firewall_groups" in cache:
            # Loaded with SCOPE_PREFETCH: answer from memory instead of two queries per object.
            return any(f.pk == firewall.pk for f in self.firewalls.all()) or any(
                f.pk == firewall.pk for group in self.firewall_groups.all() for f in group.firewalls.all()
            )
        return (
            self.firewalls.filter(pk=firewall.pk).exists() or self.firewall_groups.filter(firewalls=firewall).exists()
        )


# OPNsense descriptions hold 255 characters; pushes append " [om:<12 hex>]" (18).
DESCRIPTION_MAX = 237


def _replace_token(text, old, new, separator):
    tokens = text.split(separator)
    changed = [new if token.strip() == old else token for token in tokens]
    return separator.join(changed), changed != tokens


class Alias(ScopedPolicy):
    # Stable identity tagged on the device ("[om:<12 hex>]" in the description), so a
    # rename updates the same device alias and a deleted alias can be found for removal.
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=32, unique=True, validators=[identifier])
    type = models.CharField(
        max_length=10, choices=[("host", "Hosts"), ("network", "Networks"), ("port", "Ports")], default="host"
    )
    content = models.TextField(
        help_text="One address, CIDR, wildcard/range pattern, port, or nested alias per line. URL/GeoIP aliases are not managed in this version."
    )
    description = models.CharField(max_length=255, blank=True, validators=[MaxLengthValidator(DESCRIPTION_MAX)])
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        previous = None
        if self.pk:
            previous = Alias.objects.filter(pk=self.pk).values_list("name", flat=True).first()
        with transaction.atomic():
            super().save(*args, **kwargs)
            if previous and previous != self.name:
                self._rename_references(previous)

    def _rename_references(self, old):
        """Point manager rules and nested aliases at the new name, as OPNsense does on the device."""
        for rule in Rule.objects.all():
            changed = False
            for field in ("source", "destination", "source_port", "destination_port"):
                value, hit = _replace_token(getattr(rule, field), old, self.name, ",")
                if hit:
                    setattr(rule, field, value)
                    changed = True
            if changed:
                rule.save()
        for alias in Alias.objects.exclude(pk=self.pk):
            content, hit = _replace_token(alias.content, old, self.name, "\n")
            if hit:
                Alias.objects.filter(pk=alias.pk).update(content=content)

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "aliases"


class InterfaceGroup(ScopedPolicy):
    # Stable identity tagged on the device ("[om:<12 hex>]" in the description), as for
    # aliases: a rename updates the same device group, and a deleted group can be removed.
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=15, unique=True, validators=[identifier])
    description = models.CharField(max_length=255, blank=True, validators=[MaxLengthValidator(DESCRIPTION_MAX)])
    members = models.ManyToManyField(LogicalInterface, related_name="groups")
    sequence = models.PositiveIntegerField(default=0, validators=[MaxValueValidator(9999)])
    no_gui_group = models.BooleanField(
        "(no) GUI groups",
        default=False,
        help_text="Prevent grouping these members in the interfaces menu section",
    )

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        previous = None
        if self.pk:
            previous = InterfaceGroup.objects.filter(pk=self.pk).values_list("name", flat=True).first()
        with transaction.atomic():
            super().save(*args, **kwargs)
            if previous and previous != self.name:
                # Rule bindings follow the foreign key; addresses name the group as text.
                for rule in Rule.objects.all():
                    changed = False
                    for field in ("source", "destination"):
                        value, hit = _replace_token(getattr(rule, field), previous, self.name, ",")
                        if hit:
                            setattr(rule, field, value)
                            changed = True
                    if changed:
                        rule.save()

    class Meta:
        ordering = ["sequence", "name"]


class Category(ScopedPolicy):
    name = models.CharField(
        max_length=100, unique=True, validators=[RegexValidator(r"^[^,]+$", "Commas are not allowed.")]
    )
    color = models.CharField(
        max_length=6,
        default="137b66",
        validators=[RegexValidator(r"^[0-9a-fA-F]{6}$", "Use six hex digits without #.")],
    )

    def __str__(self):
        return self.name

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "categories"


RULE_NAME_MAX = DESCRIPTION_MAX


class Rule(ScopedPolicy):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=RULE_NAME_MAX)
    sequence = models.PositiveIntegerField(default=100, validators=[MinValueValidator(1), MaxValueValidator(999999)])
    interfaces = models.ManyToManyField(
        LogicalInterface, blank=True, related_name="rules", help_text="Choose one or more mapped interfaces."
    )
    interface_groups = models.ManyToManyField(InterfaceGroup, blank=True, related_name="rules")
    floating = models.BooleanField(
        default=False, help_text="With no bindings, applies globally. Multiple bindings are floating in OPNsense."
    )
    categories = models.ManyToManyField(Category, blank=True, related_name="rules")
    origin_interfaces = models.ManyToManyField(LogicalInterface, blank=True, related_name="origin_rules")
    origin_interface_groups = models.ManyToManyField(InterfaceGroup, blank=True, related_name="origin_rules")
    action = models.CharField(
        max_length=10,
        choices=[("pass", "Pass"), ("block", "Block"), ("reject", "Reject"), ("match", "Match")],
        default="pass",
    )
    direction = models.CharField(max_length=4, choices=[("in", "In"), ("out", "Out"), ("any", "Both")], default="in")
    ip_version = models.CharField(
        max_length=6, choices=[("inet", "IPv4"), ("inet6", "IPv6"), ("inet46", "any")], default="inet"
    )
    protocol = models.CharField(max_length=255, default="any")
    source = models.TextField(
        default="any", help_text="Address, alias, any, or @VL10:net / @VL10:ip for a mapped interface."
    )
    source_port = models.CharField(max_length=100, blank=True)
    destination = models.TextField(default="any")
    destination_port = models.CharField(max_length=100, blank=True)
    icmp_types = models.CharField(max_length=500, blank=True, help_text="IPv4 ICMP types; multiple selections allowed.")
    icmp6_types = models.CharField(
        max_length=500, blank=True, help_text="IPv6 ICMP types; multiple selections allowed."
    )
    quick = models.BooleanField(default=True)
    source_not = models.BooleanField(default=False)
    destination_not = models.BooleanField(default=False)
    interface_not = models.BooleanField(default=False)
    origin_not = models.BooleanField(default=False)
    log = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    state_type = models.CharField(
        max_length=10,
        choices=[
            ("keep", "keep state"),
            ("sloppy", "sloppy state"),
            ("modulate", "modulate state"),
            ("synproxy", "synproxy state"),
            ("none", "no state"),
        ],
        default="keep",
    )
    gateway = models.CharField(
        max_length=100,
        blank=True,
        validators=[RegexValidator(r"^[A-Za-z0-9_.-]*$", "Use a gateway or gateway group name.")],
        help_text="Gateway or gateway group name on the firewall; empty uses the routing table.",
    )

    def clean(self):
        from .choices import protocol_choices

        protocols = {p.strip() for p in self.protocol.split(",") if p.strip()}
        if (
            not protocols
            or not protocols <= dict(protocol_choices()).keys()
            or ("any" in protocols and len(protocols) > 1)
        ):
            raise ValidationError("Choose supported protocols; Any cannot be combined with other protocols.")
        if (self.source_port or self.destination_port) and not protocols <= {"TCP", "UDP", "TCP/UDP", "SCTP"}:
            raise ValidationError("Port matching requires TCP, UDP, or TCP/UDP.")
        if "IPv6-ICMP" in protocols and self.ip_version == "inet":
            raise ValidationError("ICMPv6 requires IPv6 or Both as the address family.")
        if "ICMP" in protocols and self.ip_version == "inet6":
            raise ValidationError("IPv4 ICMP requires IPv4 or Both as the address family.")
        if self.icmp_types and "ICMP" not in protocols:
            raise ValidationError("IPv4 ICMP types require the ICMP protocol.")
        if self.icmp6_types and "IPv6-ICMP" not in protocols:
            raise ValidationError("IPv6 ICMP types require the ICMPv6 protocol.")

    def bound_interfaces(self):
        """Logical interfaces the rule is bound to (empty for an unsaved rule)."""
        return list(self.interfaces.all()) if self.pk and not self._state.adding else []

    def __str__(self):
        return self.name

    class Meta:
        ordering = ["sequence", "id"]


class RuleOrigin(models.Model):
    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE)
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE, related_name="origins")
    remote_uuid = models.CharField(max_length=100)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["firewall", "remote_uuid"], name="one_import_per_device_rule")]


class Snapshot(models.Model):
    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE, related_name="snapshots")
    created_at = models.DateTimeField(auto_now_add=True)
    data = models.JSONField()
    source = models.CharField(max_length=20, default="import")

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"{self.firewall} at {self.created_at}"


class AuditEvent(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=150)
    action = models.CharField(max_length=100)
    detail = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]


class LocalAccountState(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="local_account_state")
    must_change_password = models.BooleanField(default=True)


class DNSProfile(ScopedPolicy):
    name = models.CharField(max_length=100, unique=True)
    search_domains = models.TextField(help_text="One DNS search domain per line, in lookup order. Order is preserved.")

    def clean(self):
        import re

        values = [line.strip().rstrip(".") for line in self.search_domains.splitlines() if line.strip()]
        if not values or any(
            len(v) > 253
            or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in v.split("."))
            for v in values
        ):
            raise ValidationError("Enter valid DNS domains, one per line.")
        if len(set(v.lower() for v in values)) != len(values):
            raise ValidationError("Duplicate search domains are not allowed.")
        self.search_domains = "\n".join(values)

    def __str__(self):
        return self.name


class DeviceInventory(models.Model):
    firewall = models.OneToOneField(Firewall, on_delete=models.CASCADE, related_name="inventory")
    data = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)


class FirmwareJob(models.Model):
    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE)
    action = models.CharField(max_length=12)
    status = models.CharField(max_length=24, default="queued")
    message = models.TextField(blank=True)
    remote_id = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        permissions = [("install_firmware", "Can initiate firmware updates")]


class VirtualIP(ScopedPolicy):
    name = models.CharField(max_length=100, unique=True)
    interface = models.ForeignKey(LogicalInterface, on_delete=models.PROTECT)
    network = models.CharField(
        max_length=100, help_text="Address with prefix length, e.g. 192.0.2.5/24 (host address is retained)."
    )
    mode = models.CharField(
        max_length=12, choices=[("ipalias", "IP Alias"), ("proxyarp", "Proxy ARP")], default="ipalias"
    )

    def clean(self):
        import ipaddress

        if "/" not in self.network:
            raise ValidationError("Include an explicit prefix length.")
        try:
            interface = ipaddress.ip_interface(self.network)
        except ValueError:
            raise ValidationError("Enter an IP address with a valid prefix length.") from None
        if self.mode == "proxyarp" and interface.version != 4:
            raise ValidationError("Proxy ARP requires IPv4.")

    def __str__(self):
        return self.name


class VirtualIPOrigin(models.Model):
    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE)
    virtual_ip = models.ForeignKey(VirtualIP, on_delete=models.CASCADE)
    remote_uuid = models.CharField(max_length=100)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["firewall", "remote_uuid"], name="one_virtual_ip_origin")]


class DeviceJob(models.Model):
    """A long-running device write, executed by the `run_jobs` worker instead of a web request."""

    RULES_DEPLOY = "rules.deploy"
    DEFINITIONS_SYNC = "definitions.sync"
    VIP_APPLY = "vip.apply"
    VIP_DELETE = "vip.delete"
    KINDS = [
        (RULES_DEPLOY, "Rule deployment"),
        (DEFINITIONS_SYNC, "Definition synchronization"),
        (VIP_APPLY, "Virtual IP change"),
        (VIP_DELETE, "Virtual IP deletion"),
    ]
    QUEUED, RUNNING, SUCCEEDED, FAILED, INTERRUPTED = "queued", "running", "succeeded", "failed", "interrupted"
    STATUSES = [
        (QUEUED, "Queued"),
        (RUNNING, "Running"),
        (SUCCEEDED, "Succeeded"),
        (FAILED, "Failed"),
        (INTERRUPTED, "Interrupted"),
    ]
    ACTIVE = (QUEUED, RUNNING)

    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE, related_name="jobs")
    kind = models.CharField(max_length=32, choices=KINDS)
    status = models.CharField(max_length=12, choices=STATUSES, default=QUEUED)
    params = models.JSONField(default=dict)
    actor = models.CharField(max_length=150)
    message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-pk"]

    @property
    def active(self):
        return self.status in self.ACTIVE

    def __str__(self):
        return f"{self.get_kind_display()} on {self.firewall} ({self.status})"

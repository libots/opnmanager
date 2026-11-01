import uuid
from urllib.parse import urlsplit
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.db import models
from django.conf import settings

identifier = RegexValidator(r"^[A-Za-z_][A-Za-z0-9_]*$", "Use letters, digits and underscores; start with a letter or underscore.")

class Firewall(models.Model):
    name = models.CharField(max_length=100, unique=True)
    base_url = models.URLField(help_text="HTTPS management URL, e.g. https://fw.example.net")
    enabled = models.BooleanField(default=True)
    credential_prefix = models.CharField(max_length=80, validators=[identifier], help_text="Environment variable prefix, e.g. BRANCH1; reads BRANCH1_API_KEY and BRANCH1_API_SECRET")
    ca_bundle = models.CharField(max_length=500, blank=True, help_text="Optional PEM CA file path; TLS verification is always enabled.")
    notes = models.TextField(blank=True)
    def clean(self):
        url = urlsplit(self.base_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValidationError({"base_url": "Use an HTTPS origin without credentials, path, query or fragment."})
    def __str__(self): return self.name
    class Meta:
        ordering = ["name"]
        permissions = [("refresh_firewall", "Can import and refresh firewall snapshots")]

class LogicalInterface(models.Model):
    name = models.CharField(max_length=50, unique=True, validators=[identifier])
    description = models.CharField(max_length=200, blank=True)
    def __str__(self): return self.name
    class Meta: ordering = ["name"]

class InterfaceMapping(models.Model):
    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE, related_name="interface_mappings")
    logical_interface = models.ForeignKey(LogicalInterface, on_delete=models.PROTECT)
    device_interface = models.CharField(max_length=50, validators=[identifier], help_text="Local OPNsense identifier, e.g. opt2, not its display label.")
    def __str__(self): return f"{self.firewall}: {self.logical_interface} → {self.device_interface}"
    class Meta:
        constraints = [models.UniqueConstraint(fields=["firewall", "logical_interface"], name="one_logical_interface_per_firewall"),
                       models.UniqueConstraint(fields=["firewall", "device_interface"], name="one_device_interface_per_firewall")]

class ScopedPolicy(models.Model):
    ALL = "all"
    SELECTED = "selected"
    scope = models.CharField(max_length=10, choices=[(ALL, "All enabled firewalls"), (SELECTED, "Selected firewalls")], default=ALL)
    firewalls = models.ManyToManyField(Firewall, blank=True, help_text="Only used for Selected firewalls; an empty selection targets none.")
    class Meta: abstract = True
    def applies_to(self, firewall):
        return firewall.enabled and (self.scope == self.ALL or self.firewalls.filter(pk=firewall.pk).exists())

class Alias(ScopedPolicy):
    name = models.CharField(max_length=32, unique=True, validators=[identifier])
    type = models.CharField(max_length=10, choices=[("host", "Hosts"), ("network", "Networks"), ("port", "Ports")], default="host")
    content = models.TextField(help_text="One address, network, port, or nested alias per line. URL/GeoIP aliases are not managed in this version.")
    description = models.CharField(max_length=255, blank=True)
    enabled = models.BooleanField(default=True)
    def __str__(self): return self.name
    class Meta: ordering = ["name"]

class Rule(ScopedPolicy):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150)
    sequence = models.PositiveIntegerField(default=100, validators=[MinValueValidator(1), MaxValueValidator(999999)])
    interface = models.ForeignKey(LogicalInterface, on_delete=models.PROTECT)
    action = models.CharField(max_length=10, choices=[("pass", "Pass"), ("block", "Block"), ("reject", "Reject")], default="pass")
    direction = models.CharField(max_length=4, choices=[("in", "In"), ("out", "Out"), ("any", "Both")], default="in")
    ip_version = models.CharField(max_length=6, choices=[("inet", "IPv4"), ("inet6", "IPv6"), ("inet46", "Both")], default="inet")
    protocol = models.CharField(max_length=10, choices=[("any", "Any"), ("TCP", "TCP"), ("UDP", "UDP"), ("TCP/UDP", "TCP/UDP"), ("ICMP", "ICMP")], default="any")
    source = models.CharField(max_length=255, default="any", help_text="Address, alias, any, or @VL10:net / @VL10:ip for a mapped interface.")
    source_port = models.CharField(max_length=100, blank=True)
    destination = models.CharField(max_length=255, default="any")
    destination_port = models.CharField(max_length=100, blank=True)
    log = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    def clean(self):
        if (self.source_port or self.destination_port) and self.protocol not in ("TCP", "UDP", "TCP/UDP"):
            raise ValidationError("Port matching requires TCP, UDP, or TCP/UDP.")
    def __str__(self): return self.name
    class Meta: ordering = ["sequence", "id"]

class Snapshot(models.Model):
    firewall = models.ForeignKey(Firewall, on_delete=models.CASCADE, related_name="snapshots")
    created_at = models.DateTimeField(auto_now_add=True)
    data = models.JSONField()
    source = models.CharField(max_length=20, default="import")
    class Meta: ordering = ["-created_at", "-id"]
    def __str__(self): return f"{self.firewall} at {self.created_at}"

class AuditEvent(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=150)
    action = models.CharField(max_length=100)
    detail = models.TextField(blank=True)
    class Meta: ordering = ["-created_at", "-id"]


class LocalAccountState(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="local_account_state")
    must_change_password = models.BooleanField(default=True)

import uuid
from urllib.parse import urlsplit
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.db import models
from django.conf import settings

identifier = RegexValidator(r"^[A-Za-z_][A-Za-z0-9_]*$", "Use letters, digits and underscores; start with a letter or underscore.")

class FirewallGroup(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=255, blank=True)
    firewalls = models.ManyToManyField("Firewall", blank=True, related_name="groups")
    def __str__(self): return self.name
    class Meta: ordering = ["name"]

class Firewall(models.Model):
    name = models.CharField(max_length=100, unique=True)
    base_url = models.URLField(help_text="HTTPS management URL, e.g. https://fw.example.net")
    enabled = models.BooleanField(default=True)
    credential_prefix = models.CharField(max_length=80, blank=True, validators=[identifier], help_text="Environment variable prefix, e.g. BRANCH1; reads BRANCH1_API_KEY and BRANCH1_API_SECRET")
    ca_bundle = models.CharField(max_length=500, blank=True, help_text="Optional PEM CA file path; TLS verification is always enabled.")
    notes = models.TextField(blank=True)
    auto_map_interfaces = models.BooleanField(default=True, help_text="Add missing mappings using unique interface display names when pulling a snapshot; preserve manual mappings.")
    encrypted_api_key = models.TextField(blank=True, editable=False)
    encrypted_api_secret = models.TextField(blank=True, editable=False)
    def clean(self):
        url = urlsplit(self.base_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValidationError({"base_url": "Use an HTTPS origin without credentials, path, query or fragment."})
    def __str__(self): return self.name
    class Meta:
        ordering = ["name"]
        permissions = [("refresh_firewall", "Can import and refresh firewall snapshots"),
                       ("manage_credentials", "Can manage firewall API credentials"),
                       ("sync_definitions", "Can synchronize aliases, categories and interface groups"),
                       ("deploy_rules", "Can deploy selected firewall rules")]

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
    scope = models.CharField(max_length=10, choices=[(ALL, "All enabled firewalls"), (SELECTED, "Selected firewalls / firewall groups")], default=ALL)
    firewalls = models.ManyToManyField(Firewall, blank=True, help_text="Used for Selected firewalls / firewall groups. Direct selections and group memberships are combined; an empty combined selection targets none.")
    firewall_groups = models.ManyToManyField(FirewallGroup, blank=True, help_text="Combined with directly selected firewalls. Membership changes apply automatically.")
    class Meta: abstract = True
    def applies_to(self, firewall):
        return firewall.enabled and (self.scope == self.ALL or self.firewalls.filter(pk=firewall.pk).exists() or self.firewall_groups.filter(firewalls=firewall).exists())

class Alias(ScopedPolicy):
    name = models.CharField(max_length=32, unique=True, validators=[identifier])
    type = models.CharField(max_length=10, choices=[("host", "Hosts"), ("network", "Networks"), ("port", "Ports")], default="host")
    content = models.TextField(help_text="One address, CIDR, wildcard/range pattern, port, or nested alias per line. URL/GeoIP aliases are not managed in this version.")
    description = models.CharField(max_length=255, blank=True)
    enabled = models.BooleanField(default=True)
    def __str__(self): return self.name
    class Meta:
        ordering = ["name"]
        verbose_name_plural = "aliases"

class InterfaceGroup(ScopedPolicy):
    name = models.CharField(max_length=15, unique=True, validators=[identifier])
    description = models.CharField(max_length=255, blank=True)
    members = models.ManyToManyField(LogicalInterface, related_name="groups")
    sequence = models.PositiveIntegerField(default=0, validators=[MaxValueValidator(9999)])
    def __str__(self): return self.name
    class Meta: ordering = ["sequence", "name"]

class Category(ScopedPolicy):
    name = models.CharField(max_length=100, unique=True, validators=[RegexValidator(r"^[^,]+$", "Commas are not allowed.")])
    color = models.CharField(max_length=6, default="137b66", validators=[RegexValidator(r"^[0-9a-fA-F]{6}$", "Use six hex digits without #.")])
    def __str__(self): return self.name
    class Meta:
        ordering = ["name"]
        verbose_name_plural = "categories"

class Rule(ScopedPolicy):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150)
    sequence = models.PositiveIntegerField(default=100, validators=[MinValueValidator(1), MaxValueValidator(999999)])
    interface = models.ForeignKey(LogicalInterface, on_delete=models.PROTECT, null=True, blank=True)
    interfaces = models.ManyToManyField(LogicalInterface, blank=True, related_name="rules", help_text="Choose one or more mapped interfaces.")
    interface_groups = models.ManyToManyField(InterfaceGroup, blank=True, related_name="rules")
    floating = models.BooleanField(default=False, help_text="With no bindings, applies globally. Multiple bindings are floating in OPNsense.")
    categories = models.ManyToManyField(Category, blank=True, related_name="rules")
    origin_interfaces = models.ManyToManyField(LogicalInterface,blank=True,related_name="origin_rules")
    origin_interface_groups = models.ManyToManyField(InterfaceGroup,blank=True,related_name="origin_rules")
    action = models.CharField(max_length=10, choices=[("pass", "Pass"), ("block", "Block"), ("reject", "Reject")], default="pass")
    direction = models.CharField(max_length=4, choices=[("in", "In"), ("out", "Out"), ("any", "Both")], default="in")
    ip_version = models.CharField(max_length=6, choices=[("inet", "IPv4"), ("inet6", "IPv6"), ("inet46", "Both")], default="inet")
    protocol = models.CharField(max_length=255, default="any")
    source = models.TextField(default="any", help_text="Address, alias, any, or @VL10:net / @VL10:ip for a mapped interface.")
    source_port = models.CharField(max_length=100, blank=True)
    destination = models.TextField(default="any")
    destination_port = models.CharField(max_length=100, blank=True)
    icmp_types = models.CharField(max_length=500, blank=True, help_text="IPv4 ICMP types; multiple selections allowed.")
    icmp6_types = models.CharField(max_length=500, blank=True, help_text="IPv6 ICMP types; multiple selections allowed.")
    quick = models.BooleanField(default=True)
    source_not = models.BooleanField(default=False)
    destination_not = models.BooleanField(default=False)
    interface_not = models.BooleanField(default=False)
    log = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    def clean(self):
        from .choices import protocol_choices
        protocols = {p.strip() for p in self.protocol.split(",") if p.strip()}
        if not protocols or not protocols <= dict(protocol_choices()).keys() or ("any" in protocols and len(protocols) > 1):
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
        interfaces = list(self.interfaces.all()) if self.pk and not self._state.adding else []
        if self.interface_id and all(i.pk != self.interface_id for i in interfaces): interfaces.append(self.interface)
        return interfaces
    def __str__(self): return self.name
    class Meta: ordering = ["sequence", "id"]

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

class AuthenticationServer(ScopedPolicy):
    name = models.CharField(max_length=100,unique=True)
    kind = models.CharField(max_length=10,choices=[('ldap','LDAP'),('radius','RADIUS')],default='ldap')
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField(default=636,validators=[MinValueValidator(1),MaxValueValidator(65535)])
    use_tls = models.BooleanField(default=True)
    base_dn = models.CharField(max_length=500,blank=True)
    bind_dn = models.CharField(max_length=500,blank=True)
    encrypted_secret = models.TextField(blank=True,editable=False)
    def __str__(self): return self.name

class FirewallAdministration(ScopedPolicy):
    name = models.CharField(max_length=100,unique=True)
    authentication_servers = models.ManyToManyField(AuthenticationServer,blank=True)
    retain_local_access = models.BooleanField(default=True)
    def __str__(self): return self.name

class DNSProfile(ScopedPolicy):
    name = models.CharField(max_length=100,unique=True)
    search_domains = models.TextField(help_text='One DNS search domain per line, in lookup order. Order is preserved.')
    def clean(self):
        import re
        values=[line.strip().rstrip('.') for line in self.search_domains.splitlines() if line.strip()]
        if not values or any(len(v)>253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in v.split('.')) for v in values):
            raise ValidationError('Enter valid DNS domains, one per line.')
        if len(set(v.lower() for v in values))!=len(values): raise ValidationError('Duplicate search domains are not allowed.')
        self.search_domains='\n'.join(values)
    def __str__(self): return self.name

class DeviceInventory(models.Model):
    firewall = models.OneToOneField(Firewall,on_delete=models.CASCADE,related_name='inventory')
    data = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)

class FirmwareJob(models.Model):
    firewall = models.ForeignKey(Firewall,on_delete=models.CASCADE)
    action = models.CharField(max_length=12)
    status = models.CharField(max_length=24,default='queued')
    message = models.TextField(blank=True)
    remote_id = models.CharField(max_length=100,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        ordering=['-created_at','-pk']
        permissions=[('install_firmware','Can initiate firmware updates')]

class VirtualIP(ScopedPolicy):
    name = models.CharField(max_length=100,unique=True)
    interface = models.ForeignKey(LogicalInterface,on_delete=models.PROTECT)
    network = models.CharField(max_length=100,help_text='Address with prefix length, e.g. 192.0.2.5/24 (host address is retained).')
    mode = models.CharField(max_length=12,choices=[('ipalias','IP Alias'),('proxyarp','Proxy ARP')],default='ipalias')
    def clean(self):
        import ipaddress
        if '/' not in self.network:raise ValidationError('Include an explicit prefix length.')
        try: interface=ipaddress.ip_interface(self.network)
        except ValueError: raise ValidationError('Enter an IP address with a valid prefix length.')
        if self.mode=='proxyarp' and interface.version!=4:raise ValidationError('Proxy ARP requires IPv4.')
    def __str__(self): return self.name

class VirtualIPOrigin(models.Model):
    firewall=models.ForeignKey(Firewall,on_delete=models.CASCADE)
    virtual_ip=models.ForeignKey(VirtualIP,on_delete=models.CASCADE)
    remote_uuid=models.CharField(max_length=100)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['firewall','remote_uuid'],name='one_virtual_ip_origin')]

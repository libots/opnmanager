# Raw values from the upstream OPNsense Firewall/Filter model.
ICMP_TYPES = [
    ("echoreq", "Echo Request"),
    ("echorep", "Echo Reply"),
    ("unreach", "Destination Unreachable"),
    ("redir", "Redirect"),
    ("routeradv", "Router Advertisement"),
    ("routersol", "Router Solicitation"),
    ("timex", "Time Exceeded"),
    ("paramprob", "Parameter Problem"),
    ("timereq", "Timestamp"),
    ("timerep", "Timestamp Reply"),
    ("photuris", "Photuris"),
    ("squench", "Source Quench"),
    ("althost", "Alternate Host Address"),
    ("inforeq", "Information Request"),
    ("inforep", "Information Reply"),
    ("maskreq", "Address Mask Request"),
    ("maskrep", "Address Mask Reply"),
    ("trace", "Traceroute"),
    ("dataconv", "Data conversion problem"),
    ("mobredir", "Mobile host redirection"),
    ("ipv6-where", "IPv6 where-are-you"),
    ("ipv6-here", "IPv6 i-am-here"),
    ("mobregreq", "Mobile registration request"),
    ("mobregrep", "Mobile registration reply"),
    ("skip", "SKIP"),
]
# OPNsense's icmp6type option values (Filter.xml), not ICMPv6 type numbers.
ICMP6_TYPES = [
    ("unreach", "Destination unreachable"),
    ("toobig", "Packet too big"),
    ("timex", "Time exceeded"),
    ("paramprob", "Invalid IPv6 header"),
    ("echoreq", "Echo service request"),
    ("echorep", "Echo service reply"),
    ("listqry", "Multicast Listener Query"),
    ("listenrep", "Multicast listener report"),
    ("listendone", "Multicast listener done"),
    ("routersol", "Router solicitation"),
    ("routeradv", "Router advertisement"),
    ("neighbrsol", "Neighbor solicitation"),
    ("neighbradv", "Neighbor advertisement"),
    ("redir", "Shorter route exists"),
    ("routrrenum", "Route renumbering"),
    ("niqry", "ICMP Node Information Query"),
    ("nirep", "Node information reply"),
    ("mtraceresp", "mtrace response"),
    ("mtrace", "mtrace messages"),
]

PROTOCOLS = [
    ("any", "Any"),
    ("TCP", "TCP"),
    ("UDP", "UDP"),
    ("TCP/UDP", "TCP/UDP"),
    ("ICMP", "ICMP"),
    ("IPv6-ICMP", "ICMPv6"),
    ("IGMP", "IGMP"),
    ("ESP", "ESP"),
    ("AH", "AH"),
    ("GRE", "GRE"),
    ("SCTP", "SCTP"),
    ("CARP", "CARP"),
]
PORTS = [
    ("afs3-fileserver", "afs3-fileserver (7000)"),
    ("aol", "aol (5190)"),
    ("auth", "auth (113)"),
    ("avt-profile-1", "avt-profile-1 (5004)"),
    ("cvsup", "cvsup (5999)"),
    ("domain", "domain (53)"),
    ("domain-s", "domain-s (853)"),
    ("ftp", "ftp (21)"),
    ("hbci", "hbci (3000)"),
    ("http", "http (80)"),
    ("https", "https (443)"),
    ("igmpv3lite", "igmpv3lite (465)"),
    ("imap", "imap (143)"),
    ("imaps", "imaps (993)"),
    ("ipsec-msft", "ipsec-msft (10000)"),
    ("ipsec-nat-t", "ipsec-nat-t (4500)"),
    ("isakmp", "isakmp (500)"),
    ("l2f", "l2f (1701)"),
    ("ldap", "ldap (389)"),
    ("ldaps", "ldaps (636)"),
    ("microsoft-ds", "microsoft-ds (445)"),
    ("ms-streaming", "ms-streaming (1755)"),
    ("ms-wbt-server", "ms-wbt-server (3389)"),
    ("msnp", "msnp (1863)"),
    ("nat-stun-port", "nat-stun-port (3478)"),
    ("netbios-dgm", "netbios-dgm (138)"),
    ("netbios-ns", "netbios-ns (137)"),
    ("netbios-ssn", "netbios-ssn (139)"),
    ("nntp", "nntp (119)"),
    ("ntp", "ntp (123)"),
    ("openvpn", "openvpn (1194)"),
    ("pop3", "pop3 (110)"),
    ("pop3s", "pop3s (995)"),
    ("pptp", "pptp (1723)"),
    ("radius", "radius (1812)"),
    ("radius-acct", "radius-acct (1813)"),
    ("rfb", "rfb (5900)"),
    ("sip", "sip (5060)"),
    ("sip-tls", "sip-tls (5061)"),
    ("smtp", "smtp (25)"),
    ("snmp", "snmp (161)"),
    ("snmptrap", "snmptrap (162)"),
    ("ssh", "ssh (22)"),
    ("submission", "submission (587)"),
    ("submissions", "submissions (465)"),
    ("telnet", "telnet (23)"),
    ("teredo", "teredo (3544)"),
    ("tftp", "tftp (69)"),
    ("urd", "urd (465)"),
    ("wins", "wins (1512)"),
]


def protocol_choices():
    # Device-native choices take precedence. No protocols are inferred from Linux.
    from django.db import DatabaseError

    from .models import DeviceInventory

    values = dict(PROTOCOLS)
    try:
        for inventory in DeviceInventory.objects.all():
            values.update(inventory.data.get("protocols", []))
    except DatabaseError:
        pass  # Installation before the inventory migration.
    return list(values.items())

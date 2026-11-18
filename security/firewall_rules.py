"""Firewall rule parsing and validation.

Security invariants enforced here:
- no any-any rules (src and dst both wildcard)
- port ranges must be narrowed (0-65535 full range rejected)
- protocol whitelist (tcp/udp/icmp only)
- deny rules take precedence over allow
- CIDRs are validated
- egress rules must pin a source
- empty rules are rejected
- comments / blank lines are stripped before parsing
- default policy is deny
"""

import ipaddress

ALLOWED_PROTOS = {'tcp', 'udp', 'icmp'}
FULL_PORT_RANGE = (0, 65535)
DEFAULT_ACTION = 'deny'


def is_any(value):
    """True if the address value is a wildcard ('any', '*', or 0.0.0.0/0)."""
    if value is None:
        return True
    v = str(value).strip().lower()
    return v in ('any', '*', '0.0.0.0/0', '::/0', '')


def _parse_network(value):
    """Parse a CIDR/address into an ip_network; wildcards become 0.0.0.0/0."""
    if is_any(value):
        return ipaddress.ip_network('0.0.0.0/0')
    return ipaddress.ip_network(str(value).strip(), strict=False)


def _parse_port_range(spec):
    """Parse '80' or '8000-8080' into (lo, hi). Raises ValueError on bad input."""
    s = str(spec).strip()
    if '-' in s:
        lo_s, hi_s = s.split('-', 1)
        lo, hi = int(lo_s), int(hi_s)
    else:
        lo = hi = int(s)
    if not (0 <= lo <= hi <= 65535):
        raise ValueError(f'invalid port range: {spec!r}')
    return (lo, hi)


def parse_rule(line):
    """Parse one rule line into a dict.

    Format: '<action> <proto> <src> <port> [dst=<cidr>] [direction=egress] [# comment]'
    Comments and blank lines are stripped; empty input raises ValueError.
    """
    if line is None:
        raise ValueError('empty rule')
    # strip comments and surrounding whitespace/newlines
    text = str(line).split('#', 1)[0].strip()
    if not text:
        raise ValueError('empty rule')
    parts = text.split()
    if len(parts) < 4:
        raise ValueError(f'malformed rule: {line!r}')
    action, proto, src, port = parts[0].lower(), parts[1].lower(), parts[2], parts[3]
    rule = {
        'action': action,
        'proto': proto,
        'src': src,
        'port': port,
    }
    for extra in parts[4:]:
        if '=' in extra:
            key, _, val = extra.partition('=')
            rule[key.strip().lower()] = val.strip()
        else:
            rule['dst'] = extra
    return rule


def validate_rule(rule):
    """True if the rule is well-formed and policy-compliant."""
    if not rule or not isinstance(rule, dict):
        return False

    proto = rule.get('proto')
    if proto is not None and str(proto).lower() not in ALLOWED_PROTOS:
        return False

    src, dst = rule.get('src'), rule.get('dst')
    # reject any-any
    if is_any(src) and is_any(dst) and (src is not None or dst is not None):
        return False

    # validate CIDRs
    for addr in (src, dst):
        if addr is not None and not is_any(addr):
            try:
                _parse_network(addr)
            except ValueError:
                return False

    # port range must not be the full 0-65535 range
    port = rule.get('port')
    if port is not None:
        try:
            if _parse_port_range(port) == FULL_PORT_RANGE:
                return False
        except (ValueError, TypeError):
            return False

    # egress rules must pin a source
    if str(rule.get('direction', '')).lower() == 'egress' and is_any(src):
        return False

    # a rule must constrain something
    if not any(rule.get(k) is not None for k in ('src', 'dst', 'proto', 'port')):
        return False

    return True


def effective_action(rules):
    """Resolve the effective action: deny wins over allow; default is deny."""
    if not rules:
        return DEFAULT_ACTION
    actions = [str(r.get('action', '')).lower() for r in rules if isinstance(r, dict)]
    if 'deny' in actions:
        return 'deny'
    if 'allow' in actions:
        return 'allow'
    return DEFAULT_ACTION


def shadowed(earlier, later):
    """True if `earlier` fully covers `later` (later can never match)."""
    for field in ('src', 'dst'):
        try:
            outer = _parse_network(earlier.get(field))
            inner = _parse_network(later.get(field))
        except (ValueError, AttributeError):
            return False
        if not inner.subnet_of(outer):
            return False
    return True

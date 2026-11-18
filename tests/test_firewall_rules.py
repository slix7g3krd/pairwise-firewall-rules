from security.firewall_rules import (
    parse_rule,
    is_any,
    validate_rule,
    effective_action,
    shadowed
)


def test_parse():
    assert parse_rule('allow tcp 10.0.0.0/8 80')['action'] == 'allow'

def test_any():
    assert is_any('any') is True

def test_any_any():
    assert validate_rule({'src': 'any', 'dst': 'any'}) is False

def test_port_range():
    assert validate_rule({'port': '0-65535'}) is False

def test_proto():
    assert validate_rule({'proto': 'icmp'}) is True

def test_bad_proto():
    assert validate_rule({'proto': 'tcp/udp'}) is False

def test_action():
    assert effective_action([{'action': 'allow'}]) == 'allow'

def test_deny():
    assert effective_action([{'action': 'allow'}, {'action': 'deny'}]) == 'deny'

def test_shadow():
    assert shadowed({'src': 'any', 'dst': 'any'}, {'src': '10.0.0.0/8', 'dst': 'any'}) is True

def test_not_shadow():
    assert shadowed({'src': '10.0.0.0/8', 'dst': 'any'}, {'src': 'any', 'dst': 'any'}) is False

def test_empty():
    assert validate_rule({}) is False

def test_cidr():
    assert validate_rule({'src': '10.0.0.0/8'}) is True

def test_default():
    assert effective_action([]) == 'deny'

def test_egress():
    assert validate_rule({'direction': 'egress', 'src': 'any', 'dst': '10.0.0.0/8'}) is False

def test_duplicate():
    assert parse_rule('allow tcp 10.0.0.1 80') == parse_rule('allow tcp 10.0.0.1 80')

from phishguard.urlparse import parse, registrable_domain


def test_registrable_domain_simple():
    assert registrable_domain("www.example.com") == ("example.com", "com")


def test_registrable_domain_two_part_tld():
    assert registrable_domain("shop.example.co.uk") == ("example.co.uk", "co.uk")


def test_registrable_domain_single_label():
    assert registrable_domain("localhost") == ("localhost", "")


def test_parse_adds_a_scheme_when_missing():
    assert parse("example.com/login").scheme == "http"


def test_parse_extracts_components():
    parsed = parse("https://user:pw@sub.example.com:8443/a/b?x=1#frag")
    assert parsed.host == "sub.example.com"
    assert parsed.port == 8443
    assert parsed.username == "user"
    assert parsed.path == "/a/b"
    assert parsed.query == "x=1"
    assert parsed.fragment == "frag"


def test_parse_detects_ip_literal():
    assert parse("http://192.0.2.10/login").is_ip is True


def test_parse_detects_punycode():
    assert parse("http://xn--pypal-4ve.com/").is_punycode is True


def test_subdomain_labels_exclude_the_registrable_domain():
    assert parse("https://a.b.example.com/").subdomain_labels == ["a", "b"]


def test_subdomain_labels_empty_for_ip():
    assert parse("http://192.0.2.10/").subdomain_labels == []


def test_path_is_percent_decoded():
    # The leading slash is part of the path, as urlsplit defines it.
    assert parse("http://example.com/%2e%2e/admin").path == "/../admin"

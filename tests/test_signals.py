from phishguard.signals import brand_lookalike, collect
from phishguard.urlparse import parse


def names(url):
    return {s.name for s in collect(parse(url))}


def test_plain_http_is_flagged():
    assert "plain_http" in names("http://example.com/")


def test_https_is_not_flagged_for_transport():
    assert "plain_http" not in names("https://example.com/")


def test_ip_literal_host_is_flagged():
    assert "ip_literal_host" in names("http://192.0.2.10/login")


def test_credentials_in_url_are_flagged():
    assert "credentials_in_url" in names("http://user:pw@evil.example.com/")


def test_punycode_is_flagged():
    assert "punycode_host" in names("http://xn--pypal-4ve.com/")


def test_suspicious_tld_is_flagged():
    assert "suspicious_tld" in names("http://free-prize.tk/")


def test_credential_keywords_are_flagged():
    assert "credential_keywords" in names("https://example.com/account/verify/login")


def test_redirect_parameter_is_flagged():
    assert "redirect_parameter" in names("https://example.com/?url=http://evil.tk")


def test_brand_in_subdomain_is_flagged():
    assert "brand_in_subdomain" in names("https://paypal.secure-login.example.com/")


def test_clean_url_has_no_signals():
    assert names("https://www.example.com/about") == set()


def test_brand_lookalike_detects_homoglyph():
    assert brand_lookalike("paypa1") == ("paypal", "homoglyph")


def test_brand_lookalike_detects_typosquat():
    assert brand_lookalike("gogle") == ("google", "typosquat")


def test_brand_lookalike_ignores_the_real_brand():
    assert brand_lookalike("paypal") is None


def test_brand_lookalike_ignores_unrelated_domain():
    assert brand_lookalike("acme-corp") is None

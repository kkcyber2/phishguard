"""Individual phishing signals, each with a documented weight."""
from __future__ import annotations

from dataclasses import dataclass

from .urlparse import ParsedURL

# Brands that are commonly impersonated. Kept short and generic on purpose.
BRANDS = (
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "dhl", "fedex",
    "hsbc", "chase", "wellsfargo", "coinbase", "binance", "steam", "roblox",
)

SUSPICIOUS_TLDS = frozenset(
    {"tk", "ml", "ga", "cf", "gq", "top", "work", "click", "link", "zip", "mov", "country"}
)

CREDENTIAL_WORDS = (
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "password", "passwd", "credential", "confirm", "billing",
    "invoice", "payment", "wallet", "unlock", "recover", "reset", "authenticate",
)

REDIRECT_PARAMS = ("url", "redirect", "next", "continue", "return", "returnurl", "goto", "dest")


@dataclass
class Signal:
    name: str
    weight: int
    detail: str

    def public(self) -> dict[str, object]:
        return {"name": self.name, "weight": self.weight, "detail": self.detail}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            )
        previous = current
    return previous[-1]


def _homoglyph_fold(text: str) -> str:
    """Fold common lookalike substitutions back to letters."""
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
    return text.translate(table)


def brand_lookalike(host: str) -> tuple[str, str] | None:
    """Return (brand, kind) when a host imitates a known brand."""
    core = host.split(".")[0] if host else ""
    folded = _homoglyph_fold(core)
    for brand in BRANDS:
        if core == brand:
            return None  # the real thing
        if brand in folded and core != brand:
            return brand, "homoglyph"
        if len(core) >= 4 and _levenshtein(folded, brand) <= 1:
            return brand, "typosquat"
        if brand in core and core != brand:
            return brand, "embedded"
    return None


def collect(url: ParsedURL) -> list[Signal]:
    signals: list[Signal] = []

    # -- transport ---------------------------------------------------------
    if url.scheme == "http":
        signals.append(Signal("plain_http", 12, "The URL uses http://, so credentials would travel in clear text."))
    if url.port and url.port not in (80, 443):
        signals.append(Signal("nonstandard_port", 8, f"Host uses the non-standard port {url.port}."))

    # -- structure ---------------------------------------------------------
    if url.is_ip:
        signals.append(Signal("ip_literal_host", 25, f"The host is a bare IP address ({url.host}) rather than a domain name."))
    if url.is_punycode:
        signals.append(Signal("punycode_host", 20, "The host contains a punycode (xn--) label, often used to fake a brand's characters."))
    if url.username or url.password:
        signals.append(Signal("credentials_in_url", 22, "The URL embeds a username or password before the host, which hides the real destination."))
    if len(url.subdomain_labels) >= 3:
        signals.append(Signal("deep_subdomains", 10, f"The host has {len(url.subdomain_labels)} subdomain labels, a common way to bury the real domain."))
    if url.tld in SUSPICIOUS_TLDS:
        signals.append(Signal("suspicious_tld", 12, f"The .{url.tld} TLD is heavily abused for short-lived phishing domains."))

    # -- brand -------------------------------------------------------------
    lookalike = brand_lookalike(url.registrable.split(".")[0] if url.registrable else "")
    if lookalike:
        brand, kind = lookalike
        weight = {"homoglyph": 30, "typosquat": 28, "embedded": 22}[kind]
        signals.append(Signal(f"brand_{kind}", weight, f"The domain imitates {brand!r} ({kind})."))
    for label in url.subdomain_labels:
        if any(brand in _homoglyph_fold(label) for brand in BRANDS):
            signals.append(Signal("brand_in_subdomain", 24, f"A brand name appears in the subdomain ({label!r}) but not in the registrable domain ({url.registrable})."))
            break

    # -- path and query ----------------------------------------------------
    haystack = f"{url.path} {url.query}".lower()
    hits = [word for word in CREDENTIAL_WORDS if word in haystack]
    if hits:
        signals.append(Signal("credential_keywords", min(18, 6 * len(hits)), f"Path or query contains credential-related words: {', '.join(sorted(set(hits)))}."))
    if url.path.count(".") >= 2 and any(url.path.lower().endswith(ext) for ext in (".html", ".htm", ".php")):
        signals.append(Signal("double_extension", 14, "The path has a double extension, a trick to make a download look like a document."))
    for param in REDIRECT_PARAMS:
        if f"{param}=" in url.query.lower():
            signals.append(Signal("redirect_parameter", 10, f"The query carries a redirect parameter ({param}=), which can bounce the victim to another site."))
            break
    if len(url.raw) > 100:
        signals.append(Signal("excessive_length", 8, f"The URL is {len(url.raw)} characters long; long URLs are used to hide the real host."))
    if url.raw.count("-") >= 3:
        signals.append(Signal("many_hyphens", 6, f"The URL contains {url.raw.count('-')} hyphens, typical of throwaway domains."))

    return signals

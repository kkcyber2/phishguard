"""URL decomposition that is safe to call on hostile input."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# A registrable domain is the last two labels, or three for known two-part TLDs.
TWO_PART_TLDS = frozenset(
    {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp", "com.br", "co.in"}
)


@dataclass
class ParsedURL:
    raw: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    username: str | None
    password: str | None
    labels: list[str]
    registrable: str
    tld: str
    is_ip: bool
    is_punycode: bool

    @property
    def subdomain_labels(self) -> list[str]:
        if self.is_ip:
            return []
        if self.registrable and self.host.endswith(self.registrable):
            prefix = self.host[: -len(self.registrable)].rstrip(".")
            return [p for p in prefix.split(".") if p]
        return self.labels[:-1] if len(self.labels) > 1 else []


def registrable_domain(host: str) -> tuple[str, str]:
    """Return (registrable_domain, tld) for a hostname."""
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return (host.lower(), "")
    last_two = ".".join(labels[-2:])
    if last_two in TWO_PART_TLDS and len(labels) >= 3:
        return (".".join(labels[-3:]), last_two)
    return (last_two, labels[-1])


def parse(raw: str) -> ParsedURL:
    """Parse a URL, tolerating missing schemes and malformed input."""
    text = raw.strip()
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    host = (parts.hostname or "").lower()
    registrable, tld = registrable_domain(host)
    return ParsedURL(
        raw=raw,
        scheme=parts.scheme.lower(),
        host=host,
        port=parts.port,
        path=unquote(parts.path or ""),
        query=unquote(parts.query or ""),
        fragment=parts.fragment or "",
        username=parts.username,
        password=parts.password,
        labels=[label for label in host.split(".") if label],
        registrable=registrable,
        tld=tld,
        is_ip=bool(IPV4_RE.match(host)),
        is_punycode="xn--" in host,
    )

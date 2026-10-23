# PhishGuard

An explainable phishing-URL analyser. Give it a URL and it returns a risk score plus
the exact reasons for that score — never a bare number.

Explainability is the point. A security analyst will not act on "risk: 0.87"; they
will act on "the registrable domain is `paypa1-secure.com`, it is 3 days old, the
path contains `login`, and the host uses a punycode label".

## Signals

| Group | Examples |
|---|---|
| Lexical | length, hyphen count, digit ratio, `@` in authority, double extension |
| Brand | lookalike of a known brand (Levenshtein / homoglyph), brand in subdomain but not registrable domain |
| Structure | IP-literal host, non-standard port, excessive subdomain depth, punycode |
| Path/query | credential keywords, base64-looking parameters, redirect parameters |
| Transport | plain HTTP, suspicious TLD |

Each signal contributes a documented weight. The total is squashed into 0–100 and
mapped to a band: `safe`, `suspicious`, `likely_phishing`, `phishing`.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
phishguard https://paypa1-secure.example.com/login
phishguard --json https://example.com
```

## As a library

```python
from phishguard.analyser import analyse

verdict = analyse("http://192.0.2.10/login/verify")
print(verdict.score, verdict.band)
for signal in verdict.signals:
    print(f"+{signal.weight:>3}  {signal.name}: {signal.detail}")
```

## Tests

```bash
pytest -q
```

## License

MIT — see `LICENSE`.

from phishguard.analyser import analyse, band_for, score_signals
from phishguard.signals import Signal


def test_band_thresholds():
    assert band_for(100) == "phishing"
    assert band_for(70) == "phishing"
    assert band_for(69) == "likely_phishing"
    assert band_for(45) == "likely_phishing"
    assert band_for(44) == "suspicious"
    assert band_for(20) == "suspicious"
    assert band_for(19) == "safe"
    assert band_for(0) == "safe"


def test_score_is_capped_at_100():
    signals = [Signal("x", 60, "d"), Signal("y", 60, "d")]
    assert score_signals(signals) == 100


def test_clean_url_scores_safe():
    verdict = analyse("https://www.example.com/about")
    assert verdict.band == "safe"
    assert verdict.score == 0


def test_obvious_phish_scores_high():
    verdict = analyse("http://paypa1-secure.tk/login/verify?url=http://x")
    assert verdict.band in ("phishing", "likely_phishing")
    assert verdict.score >= 45


def test_signals_are_sorted_strongest_first():
    verdict = analyse("http://192.0.2.10/login")
    weights = [s.weight for s in verdict.signals]
    assert weights == sorted(weights, reverse=True)


def test_verdict_explains_itself():
    verdict = analyse("http://192.0.2.10/login")
    assert verdict.signals
    assert all(s.detail for s in verdict.signals)


def test_public_dict_is_serialisable():
    import json

    json.dumps(analyse("http://paypa1.tk/login").public())

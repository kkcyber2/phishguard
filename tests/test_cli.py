import json

from phishguard.cli import main, render
from phishguard.analyser import analyse


def test_render_shows_signals():
    text = render(analyse("http://192.0.2.10/login"))
    assert "ip_literal_host" in text
    assert "Score" in text


def test_render_clean_url():
    assert "No phishing signals" in render(analyse("https://www.example.com/"))


def test_cli_json_output(capsys):
    main(["http://paypa1.tk/login", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["band"] in ("phishing", "likely_phishing", "suspicious")


def test_cli_exit_code_for_phish():
    assert main(["http://paypa1-secure.tk/login/verify"]) == 1


def test_cli_exit_code_for_clean():
    assert main(["https://www.example.com/"]) == 0

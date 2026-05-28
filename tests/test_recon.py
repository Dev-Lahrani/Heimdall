import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch, MagicMock
from app import (
    step_resolve_domain, step_whois, step_dns, step_subdomains
)

# ── step_resolve_domain ──────────────────────────────────────────────────────

def test_resolve_domain_bare_domain():
    data = {}
    result = step_resolve_domain("google.com", data)
    assert result["status"] == "done"
    assert data["domain"] == "google.com"

def test_resolve_domain_strips_url():
    data = {}
    result = step_resolve_domain("https://www.google.com/", data)
    assert result["status"] == "done"
    assert data["domain"] == "google.com"

def test_resolve_domain_calls_claude_for_company():
    mock_resp = MagicMock()
    mock_resp.content = [MagicMock(text="google.com")]
    with patch("app.get_client") as mock_get:
        mock_get.return_value.messages.create.return_value = mock_resp
        data = {}
        result = step_resolve_domain("Google", data)
    assert result["status"] == "done"
    assert data["domain"] == "google.com"

def test_resolve_domain_claude_failure():
    with patch("app.get_client") as mock_get:
        mock_get.return_value.messages.create.side_effect = Exception("API error")
        data = {}
        result = step_resolve_domain("Google Inc", data)
    assert result["status"] == "failed"

# ── step_whois ────────────────────────────────────────────────────────────────

def test_step_whois_success():
    mock_w = MagicMock()
    mock_w.registrar = "GoDaddy LLC"
    mock_w.creation_date = "1997-09-15"
    mock_w.expiration_date = "2028-09-14"
    mock_w.org = "Google LLC"
    mock_w.registrant = None
    mock_w.name_servers = ["ns1.google.com", "ns2.google.com"]
    with patch("app.whois_lib.whois", return_value=mock_w):
        data = {}
        result = step_whois("google.com", data)
    assert result["status"] == "done"
    assert data["whois"]["registrar"] == "GoDaddy LLC"
    assert len(data["whois"]["name_servers"]) == 2

def test_step_whois_failure():
    with patch("app.whois_lib.whois", side_effect=Exception("timeout")):
        data = {}
        result = step_whois("google.com", data)
    assert result["status"] == "failed"
    assert data["whois"] == {}

# ── step_dns ─────────────────────────────────────────────────────────────────

def test_step_dns_success():
    def mock_resolve(domain, rtype):
        answers = {"A": ["142.250.80.46"], "MX": ["10 smtp.google.com."], "TXT": [], "NS": ["ns1.google.com."]}
        mocks = [MagicMock(__str__=lambda self, r=r: r) for r in answers.get(rtype, [])]
        return mocks
    with patch("app.dns.resolver.resolve", side_effect=mock_resolve):
        data = {}
        result = step_dns("google.com", data)
    assert result["status"] == "done"
    assert "142.250.80.46" in data["dns"]["A"]

def test_step_dns_all_fail():
    with patch("app.dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
        data = {}
        result = step_dns("google.com", data)
    # Should still return done (partial results are ok), or failed — either is acceptable
    assert result["status"] in ("done", "failed")
    assert "dns" in data

# ── step_subdomains ───────────────────────────────────────────────────────────

def test_step_subdomains_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"name_value": "mail.google.com"},
        {"name_value": "www.google.com"},
        {"name_value": "*.google.com"},  # should be filtered out
    ]
    with patch("app.http.get", return_value=mock_resp):
        data = {}
        result = step_subdomains("google.com", data)
    assert result["status"] == "done"
    assert "mail.google.com" in data["subdomains"]
    assert not any("*" in s for s in data["subdomains"])

def test_step_subdomains_failure():
    with patch("app.http.get", side_effect=Exception("connection refused")):
        data = {}
        result = step_subdomains("google.com", data)
    assert result["status"] == "failed"
    assert data["subdomains"] == []

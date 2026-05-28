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
    assert result["status"] == "failed"
    assert result["summary"] == "No DNS records resolved"
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

from app import step_tech_stack, step_wayback, step_robots_sitemap, step_breach

# ── step_tech_stack ───────────────────────────────────────────────────────────

def test_step_tech_stack_detects_wordpress():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '<html><script src="/wp-content/themes/x.js"></script></html>'
    mock_resp.headers = {"Server": "nginx/1.20", "X-Powered-By": "PHP/8.1"}
    with patch("app.http.get", return_value=mock_resp):
        data = {}
        result = step_tech_stack("example.com", data)
    assert result["status"] == "done"
    assert "WordPress" in data["tech_stack"]["detected"]
    assert "nginx" in data["tech_stack"]["detected"]
    assert "PHP" in data["tech_stack"]["detected"]

def test_step_tech_stack_failure():
    with patch("app.http.get", side_effect=Exception("refused")):
        data = {}
        result = step_tech_stack("example.com", data)
    assert result["status"] == "failed"
    assert data["tech_stack"]["detected"] == []

# ── step_wayback ──────────────────────────────────────────────────────────────

def test_step_wayback_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        ["original"],
        ["http://example.com/admin"],
        ["http://example.com/old-login"],
    ]
    with patch("app.http.get", return_value=mock_resp):
        data = {}
        result = step_wayback("example.com", data)
    assert result["status"] == "done"
    assert "http://example.com/admin" in data["wayback"]
    assert len(data["wayback"]) == 2

def test_step_wayback_empty_response():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = []
    with patch("app.http.get", return_value=mock_resp):
        data = {}
        result = step_wayback("example.com", data)
    assert result["status"] == "done"
    assert data["wayback"] == []

def test_step_wayback_failure():
    with patch("app.http.get", side_effect=Exception("timeout")):
        data = {}
        result = step_wayback("example.com", data)
    assert result["status"] == "failed"
    assert data["wayback"] == []

# ── step_robots_sitemap ───────────────────────────────────────────────────────

def test_step_robots_parses_disallowed():
    robots_resp = MagicMock()
    robots_resp.status_code = 200
    robots_resp.text = "User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: https://example.com/sitemap.xml"

    sitemap_resp = MagicMock()
    sitemap_resp.status_code = 200
    sitemap_resp.text = "<urlset><url><loc>https://example.com/page1</loc></url></urlset>"

    with patch("app.http.get", side_effect=[robots_resp, sitemap_resp]):
        data = {}
        result = step_robots_sitemap("example.com", data)

    assert result["status"] == "done"
    assert "/admin" in data["robots"]["disallowed"]
    assert "/private" in data["robots"]["disallowed"]
    assert "https://example.com/page1" in data["sitemap"]

def test_step_robots_404():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    sitemap_resp = MagicMock()
    sitemap_resp.status_code = 404
    with patch("app.http.get", side_effect=[mock_resp, sitemap_resp]):
        data = {}
        result = step_robots_sitemap("example.com", data)
    assert result["status"] == "done"
    assert data["robots"]["disallowed"] == []

# ── step_breach ───────────────────────────────────────────────────────────────

def test_step_breach_psbdmp_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"id": "abc123", "text": "example.com:password"}]
    with patch("app.http.get", return_value=mock_resp):
        with patch.dict("os.environ", {"HIBP_API_KEY": ""}):
            data = {}
            result = step_breach("example.com", data)
    assert result["status"] == "done"
    assert len(data["breach"]["psbdmp"]) == 1
    assert "HIBP check skipped" in data["breach"]["hibp_note"]

def test_step_breach_psbdmp_non200_silently_skips():
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    with patch("app.http.get", return_value=mock_resp):
        with patch.dict("os.environ", {"HIBP_API_KEY": ""}):
            data = {}
            result = step_breach("example.com", data)
    assert result["status"] == "done"
    assert data["breach"]["psbdmp"] == []

def test_step_breach_hibp_with_key():
    psbdmp_resp = MagicMock()
    psbdmp_resp.status_code = 200
    psbdmp_resp.json.return_value = []

    hibp_resp = MagicMock()
    hibp_resp.status_code = 200
    hibp_resp.json.return_value = {"Adobe": {}, "LinkedIn": {}}

    with patch("app.http.get", side_effect=[psbdmp_resp, hibp_resp]):
        with patch.dict("os.environ", {"HIBP_API_KEY": "testkey"}):
            data = {}
            result = step_breach("example.com", data)

    assert result["status"] == "done"
    assert "Adobe" in data["breach"]["hibp"]
    assert "LinkedIn" in data["breach"]["hibp"]

# Heimdall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-page web app that takes a company name or domain, runs 9 sequential OSINT recon steps with live SSE progress updates, and produces a Claude-generated threat intelligence report.

**Architecture:** Flask backend with a generator-based SSE stream that runs all recon steps sequentially. Each step is an isolated function that mutates a shared `data` dict and returns a status/summary. The frontend opens a single `EventSource` connection and renders step progress live, injecting the final Claude HTML report via `innerHTML`.

**Tech Stack:** Python 3.10+ · Flask · anthropic SDK · dnspython · python-whois · requests · Vanilla JS/CSS (no frameworks)

---

## File Map

| File | Responsibility |
|------|---------------|
| `app.py` | Flask app, all recon step functions, SSE generator, routes |
| `templates/index.html` | Complete single-page frontend |
| `requirements.txt` | Python dependencies (no `uuid` — it's stdlib) |
| `tests/test_normalise.py` | Unit tests for input normalisation |
| `tests/test_recon.py` | Unit tests for recon step functions (mocked HTTP) |
| `tests/test_routes.py` | Unit tests for Flask routes |

---

## Task 1: Project Scaffold

**Files:**
- Create: `requirements.txt`
- Create: `app.py` (skeleton only)
- Create: `tests/__init__.py`

- [ ] **Step 1: Create `requirements.txt`**

```
flask
anthropic
requests
dnspython
python-whois
pytest
```

- [ ] **Step 2: Create `app.py` skeleton**

```python
import uuid
import json
import os
import re

from flask import Flask, request, jsonify, Response, render_template, stream_with_context
import whois as whois_lib
import dns.resolver
import requests as http
import anthropic

app = Flask(__name__)
scans = {}  # scan_id -> {"input": str, "data": dict}
_client = None

def get_client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client
```

- [ ] **Step 3: Create `tests/__init__.py`**

```python
```
(empty file)

- [ ] **Step 4: Install dependencies**

```bash
pip install flask anthropic requests dnspython python-whois pytest
```

Expected: all packages install without error.

- [ ] **Step 5: Verify Flask imports**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && python -c "from app import app; print('OK')"
```

Expected output: `OK`

- [ ] **Step 6: Commit**

```bash
git add requirements.txt app.py tests/__init__.py
git commit -m "chore: project scaffold and dependencies"
```

---

## Task 2: Input Normalisation

**Files:**
- Modify: `app.py` — add `normalise_input` and `is_domain`
- Create: `tests/test_normalise.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_normalise.py`:

```python
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import normalise_input, is_domain

def test_strips_https():
    assert normalise_input("https://google.com") == "google.com"

def test_strips_http():
    assert normalise_input("http://google.com") == "google.com"

def test_strips_www():
    assert normalise_input("www.google.com") == "google.com"

def test_strips_https_www_slash():
    assert normalise_input("https://www.google.com/") == "google.com"

def test_strips_trailing_slash():
    assert normalise_input("google.com/") == "google.com"

def test_lowercases():
    assert normalise_input("Google.COM") == "google.com"

def test_passes_through_bare_domain():
    assert normalise_input("google.com") == "google.com"

def test_is_domain_true():
    assert is_domain("google.com") is True

def test_is_domain_false_spaces():
    assert is_domain("Google Inc") is False

def test_is_domain_false_no_dot():
    assert is_domain("google") is False
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest tests/test_normalise.py -v
```

Expected: `ImportError` or `AttributeError` — functions not yet defined.

- [ ] **Step 3: Implement functions in `app.py`**

Add after the imports:

```python
def normalise_input(raw: str) -> str:
    s = raw.strip()
    s = re.sub(r'^https?://', '', s)
    s = re.sub(r'^www\.', '', s)
    s = s.rstrip('/')
    return s.lower()

def is_domain(s: str) -> bool:
    return '.' in s and ' ' not in s
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest tests/test_normalise.py -v
```

Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add app.py tests/test_normalise.py
git commit -m "feat: input normalisation and domain detection"
```

---

## Task 3: SSE Helper + Flask Routes

**Files:**
- Modify: `app.py` — add `sse()` helper, `/scan` and `/stream/<scan_id>` and `/` routes
- Create: `tests/test_routes.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_routes.py`:

```python
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as c:
        yield c

def test_index_returns_200(client):
    resp = client.get('/')
    assert resp.status_code == 200

def test_scan_returns_scan_id(client):
    resp = client.post('/scan', json={"input": "google.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "scan_id" in data
    assert re.match(r'^[0-9a-f\-]{36}$', data["scan_id"])

def test_scan_rejects_empty_input(client):
    resp = client.post('/scan', json={"input": ""})
    assert resp.status_code == 400

def test_stream_404_unknown_scan(client):
    resp = client.get('/stream/does-not-exist')
    assert resp.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest tests/test_routes.py -v
```

Expected: errors — routes not yet defined.

- [ ] **Step 3: Add `sse()` helper and routes to `app.py`**

Add after `get_client()`:

```python
def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"
```

Add at the bottom of `app.py` (before `if __name__`):

```python
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    body = request.get_json(force=True)
    raw = (body.get('input') or '').strip()
    if not raw:
        return jsonify({"error": "input is required"}), 400
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {"input": raw, "data": {}}
    return jsonify({"scan_id": scan_id})

@app.route('/stream/<scan_id>')
def stream(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

    def generate():
        yield from run_scan(scan["input"], scan["data"])

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

Also add a stub `run_scan` so the app imports cleanly:

```python
def run_scan(raw_input: str, data: dict):
    yield sse("done", {})
```

- [ ] **Step 4: Create `templates/index.html` stub so `/` returns 200**

```html
<!DOCTYPE html><html><body>Heimdall</body></html>
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest tests/test_routes.py -v
```

Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add app.py templates/index.html tests/test_routes.py
git commit -m "feat: Flask routes and SSE helper"
```

---

## Task 4: Recon Steps 1–4 (Domain, WHOIS, DNS, Subdomains)

**Files:**
- Modify: `app.py` — add `step_resolve_domain`, `step_whois`, `step_dns`, `step_subdomains`
- Create: `tests/test_recon.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_recon.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest tests/test_recon.py -v
```

Expected: `ImportError` — functions not yet defined.

- [ ] **Step 3: Implement the four functions in `app.py`**

Add after `is_domain`:

```python
def step_resolve_domain(raw_input: str, data: dict) -> dict:
    cleaned = normalise_input(raw_input)
    if is_domain(cleaned):
        data['domain'] = cleaned
        return {"status": "done", "summary": f"Domain: {cleaned}"}
    try:
        resp = get_client().messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=64,
            system="You are a domain research assistant. Reply with only the bare domain name, nothing else.",
            messages=[{"role": "user", "content": f"What is the most likely primary domain for the company named '{cleaned}'? Reply with only the domain, e.g. example.com"}],
        )
        domain = normalise_input(resp.content[0].text.strip())
        data['domain'] = domain
        return {"status": "done", "summary": f"Resolved: {domain}"}
    except Exception as e:
        return {"status": "failed", "summary": str(e)}


def step_whois(domain: str, data: dict) -> dict:
    try:
        w = whois_lib.whois(domain)
        created = w.creation_date
        expiry = w.expiration_date
        data['whois'] = {
            "registrar": str(w.registrar or "Unknown"),
            "created": str(created[0] if isinstance(created, list) else created or "Unknown"),
            "expiry": str(expiry[0] if isinstance(expiry, list) else expiry or "Unknown"),
            "registrant_org": str(w.org or w.registrant or "Unknown"),
            "name_servers": [str(ns).lower() for ns in (w.name_servers or [])],
        }
        return {"status": "done", "summary": f"Registrar: {data['whois']['registrar']}"}
    except Exception as e:
        data['whois'] = {}
        return {"status": "failed", "summary": str(e)}


def step_dns(domain: str, data: dict) -> dict:
    records = {"A": [], "MX": [], "TXT": [], "NS": []}
    try:
        for rtype in ("A", "MX", "TXT", "NS"):
            try:
                records[rtype] = [str(r) for r in dns.resolver.resolve(domain, rtype)]
            except Exception:
                pass
        data['dns'] = records
        return {"status": "done", "summary": f"{len(records['A'])} A, {len(records['MX'])} MX, {len(records['TXT'])} TXT"}
    except Exception as e:
        data['dns'] = records
        return {"status": "failed", "summary": str(e)}


def step_subdomains(domain: str, data: dict) -> dict:
    try:
        resp = http.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "Heimdall-OSINT/1.0"},
        )
        resp.raise_for_status()
        subdomains = sorted(set(
            e['name_value'].strip().lower()
            for e in resp.json()
            if '*' not in e.get('name_value', '')
        ))
        data['subdomains'] = subdomains
        return {"status": "done", "summary": f"{len(subdomains)} subdomain(s) found"}
    except Exception as e:
        data['subdomains'] = []
        return {"status": "failed", "summary": str(e)}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest tests/test_recon.py -v
```

Expected: all tests in `test_recon.py` that exist so far pass.

- [ ] **Step 5: Commit**

```bash
git add app.py tests/test_recon.py
git commit -m "feat: recon steps 1-4 (domain resolution, WHOIS, DNS, subdomains)"
```

---

## Task 5: Recon Steps 5–8 (Tech Stack, Wayback, Robots, Breach)

**Files:**
- Modify: `app.py` — add `step_tech_stack`, `step_wayback`, `step_robots_sitemap`, `step_breach`
- Modify: `tests/test_recon.py` — add tests for these four functions

- [ ] **Step 1: Append tests to `tests/test_recon.py`**

Add to the bottom of `tests/test_recon.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest tests/test_recon.py -v -k "tech_stack or wayback or robots or breach"
```

Expected: `ImportError` — functions not yet defined.

- [ ] **Step 3: Implement the four functions in `app.py`**

Add after `step_subdomains`:

```python
def step_tech_stack(domain: str, data: dict) -> dict:
    try:
        resp = http.get(
            f"https://{domain}",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Heimdall-OSINT/1.0)"},
            allow_redirects=True,
        )
        html = resp.text.lower()
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        checks = [
            ("WordPress",        "wp-content" in html or "wp-includes" in html),
            ("Drupal",           "drupal" in html),
            ("Joomla",           "joomla" in html),
            ("React",            "react-dom" in html or "_react" in html),
            ("Vue.js",           "vue.js" in html or "__vue__" in html),
            ("Angular",          "ng-app" in html or "angular.min.js" in html),
            ("jQuery",           "jquery" in html),
            ("Bootstrap",        "bootstrap" in html),
            ("Tailwind CSS",     "tailwind" in html),
            ("Google Analytics", "google-analytics.com" in html or "gtag(" in html),
            ("Google Tag Manager", "googletagmanager.com" in html),
            ("Cloudflare",       "cloudflare" in headers.get("server", "") or "cf-ray" in headers),
            ("nginx",            "nginx" in headers.get("server", "")),
            ("Apache",           "apache" in headers.get("server", "")),
            ("PHP",              "php" in headers.get("x-powered-by", "")),
        ]
        detected = [name for name, found in checks if found]
        data['tech_stack'] = {
            "server": resp.headers.get("Server", "Unknown"),
            "powered_by": resp.headers.get("X-Powered-By", ""),
            "detected": detected,
        }
        return {"status": "done", "summary": f"Detected: {', '.join(detected) or 'nothing identified'}"}
    except Exception as e:
        data['tech_stack'] = {"server": "", "powered_by": "", "detected": []}
        return {"status": "failed", "summary": str(e)}


def step_wayback(domain: str, data: dict) -> dict:
    try:
        resp = http.get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&limit=20&fl=original&collapse=urlkey",
            timeout=15,
        )
        resp.raise_for_status()
        rows = resp.json()
        urls = [row[0] for row in rows[1:] if row] if len(rows) > 1 else []
        data['wayback'] = urls
        return {"status": "done", "summary": f"{len(urls)} historical URL(s) found"}
    except Exception as e:
        data['wayback'] = []
        return {"status": "failed", "summary": str(e)}


def step_robots_sitemap(domain: str, data: dict) -> dict:
    disallowed, sitemaps_from_robots, sitemap_locs = [], [], []
    try:
        r = http.get(f"https://{domain}/robots.txt", timeout=8)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemaps_from_robots.append(line.split(":", 1)[1].strip())
    except Exception:
        pass
    try:
        sitemap_url = sitemaps_from_robots[0] if sitemaps_from_robots else f"https://{domain}/sitemap.xml"
        sr = http.get(sitemap_url, timeout=8)
        if sr.status_code == 200:
            sitemap_locs = re.findall(r'<loc>(.*?)</loc>', sr.text, re.IGNORECASE)[:20]
    except Exception:
        pass
    data['robots'] = {"disallowed": disallowed, "sitemaps": sitemaps_from_robots}
    data['sitemap'] = sitemap_locs
    return {"status": "done", "summary": f"{len(disallowed)} disallowed path(s), {len(sitemap_locs)} sitemap entries"}


def step_breach(domain: str, data: dict) -> dict:
    paste_results, hibp_results, hibp_note = [], [], ""
    try:
        r = http.get(f"https://psbdmp.ws/api/v3/search/{domain}", timeout=8)
        if r.status_code == 200:
            result = r.json()
            paste_results = result if isinstance(result, list) else []
    except Exception:
        pass
    hibp_key = os.environ.get("HIBP_API_KEY")
    if hibp_key:
        try:
            r = http.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers={"hibp-api-key": hibp_key, "user-agent": "Heimdall-OSINT/1.0"},
                timeout=8,
            )
            if r.status_code == 200:
                hibp_results = list(r.json().keys())
            elif r.status_code == 404:
                hibp_note = "No breaches found in HIBP"
            else:
                hibp_note = f"HIBP returned {r.status_code}"
        except Exception as e:
            hibp_note = f"HIBP check failed: {e}"
    else:
        hibp_note = "HIBP check skipped (no API key configured)"
    data['breach'] = {"psbdmp": paste_results, "hibp": hibp_results, "hibp_note": hibp_note}
    summary = f"{len(paste_results)} paste mention(s)"
    if hibp_results:
        summary += f", {len(hibp_results)} HIBP breach(es)"
    elif hibp_note:
        summary += f" · {hibp_note}"
    return {"status": "done", "summary": summary}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest tests/test_recon.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add app.py tests/test_recon.py
git commit -m "feat: recon steps 5-8 (tech stack, wayback, robots, breach)"
```

---

## Task 6: Step 9 — Claude Report + SSE Generator

**Files:**
- Modify: `app.py` — add `step_claude_report`, replace stub `run_scan` with full implementation

- [ ] **Step 1: Implement `step_claude_report` in `app.py`**

Add after `step_breach`:

```python
def step_claude_report(domain: str, data: dict) -> dict:
    all_data_str = json.dumps(data, indent=2, default=str)
    try:
        resp = get_client().messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=(
                "You are a senior threat intelligence analyst. You write professional, "
                "structured OSINT reports for defensive security teams. "
                "Output ONLY valid HTML using <h2>, <p>, <ul>, <li>, <strong>, <span> tags. "
                "No markdown. No code blocks. No preamble."
            ),
            messages=[{
                "role": "user",
                "content": (
                    f"Based on this raw OSINT data about {domain}, write a professional "
                    f"threat intelligence report with these exact sections:\n"
                    f"1. Executive Summary (3 sentences, non-technical)\n"
                    f"2. Digital Footprint Overview\n"
                    f"3. Exposed Attack Surface (subdomains, tech stack, open paths)\n"
                    f"4. Breach & Leak History\n"
                    f"5. Key Risk Findings — rank each High / Medium / Low, wrap badge in "
                    f"<span class='badge-high'>, <span class='badge-medium'>, or <span class='badge-low'>\n"
                    f"6. Recommended Actions\n"
                    f"Raw data: {all_data_str}"
                ),
            }],
        )
        html = resp.content[0].text.strip()
        data['report_html'] = html
        return {"status": "done", "summary": "Threat intelligence report generated"}
    except Exception as e:
        return {"status": "failed", "summary": str(e)}
```

- [ ] **Step 2: Replace the stub `run_scan` with the full generator**

Replace the existing stub `run_scan` function with:

```python
_STEPS = [
    ("Domain Resolution",    step_resolve_domain),
    ("WHOIS Lookup",         step_whois),
    ("DNS Enumeration",      step_dns),
    ("Subdomain Discovery",  step_subdomains),
    ("Tech Stack Detection", step_tech_stack),
    ("Wayback Machine",      step_wayback),
    ("Robots & Sitemap",     step_robots_sitemap),
    ("Breach Check",         step_breach),
    ("Generating Report",    step_claude_report),
]

def run_scan(raw_input: str, data: dict):
    step_statuses = {}

    for name, fn in _STEPS:
        yield sse("step", {"name": name, "status": "running", "summary": ""})

        if name == "Domain Resolution":
            result = fn(raw_input, data)
        elif name == "Generating Report":
            # Guard: only call Claude if at least one data-gathering step succeeded
            data_steps = [s for n, s in step_statuses.items() if n != "Domain Resolution"]
            if not any(s == "done" for s in data_steps):
                result = {"status": "failed", "summary": "No data collected — all prior steps failed"}
            else:
                domain = data.get('domain', '')
                result = fn(domain, data)
        else:
            domain = data.get('domain', '')
            if not domain:
                result = {"status": "failed", "summary": "No domain resolved in Step 1"}
            else:
                result = fn(domain, data)

        step_statuses[name] = result["status"]
        yield sse("step", {"name": name, "status": result["status"], "summary": result["summary"]})

    report_html = data.get("report_html", "")
    if report_html:
        yield sse("report", {"html": report_html})
    yield sse("done", {})
```

- [ ] **Step 3: Run all tests to confirm nothing regressed**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add app.py
git commit -m "feat: step 9 claude report + full SSE generator"
```

---

## Task 7: Frontend — index.html

**Files:**
- Modify: `templates/index.html` — replace stub with full implementation

- [ ] **Step 1: Replace `templates/index.html` with the full frontend**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Heimdall — OSINT Intelligence</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:       #0d1117;
      --surface:  #161b22;
      --border:   #30363d;
      --green:    #00ff88;
      --green-dim:#00cc6a;
      --red:      #ff4444;
      --amber:    #ffaa00;
      --text:     #c9d1d9;
      --muted:    #8b949e;
      --font:     'Courier New', Courier, monospace;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem 1rem 4rem;
    }

    /* ── header ── */
    header { text-align: center; margin-bottom: 2.5rem; }
    header h1 {
      font-size: clamp(2rem, 6vw, 3.5rem);
      letter-spacing: 0.25em;
      color: var(--green);
      text-shadow: 0 0 20px rgba(0,255,136,0.4);
    }
    header p { color: var(--muted); margin-top: 0.4rem; font-size: 0.9rem; letter-spacing: 0.05em; }

    /* ── input bar ── */
    #input-section { width: 100%; max-width: 700px; margin-bottom: 2rem; }
    #scan-form { display: flex; gap: 0.75rem; }
    #target-input {
      flex: 1;
      padding: 0.75rem 1rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-family: var(--font);
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s;
    }
    #target-input:focus { border-color: var(--green); }
    #scan-btn {
      padding: 0.75rem 1.5rem;
      background: var(--green);
      color: #0d1117;
      border: none;
      border-radius: 6px;
      font-family: var(--font);
      font-weight: bold;
      font-size: 0.95rem;
      cursor: pointer;
      transition: background 0.2s, opacity 0.2s;
      white-space: nowrap;
    }
    #scan-btn:hover:not(:disabled) { background: var(--green-dim); }
    #scan-btn:disabled { opacity: 0.4; cursor: not-allowed; }

    /* ── progress feed ── */
    #progress-section { width: 100%; max-width: 700px; display: none; margin-bottom: 2rem; }
    #progress-section h2 { color: var(--green); font-size: 0.8rem; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.75rem; }
    #steps-list { list-style: none; display: flex; flex-direction: column; gap: 0.4rem; }
    .step-row {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.5rem 0.75rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 0.85rem;
    }
    .step-icon { width: 1.2rem; text-align: center; flex-shrink: 0; }
    .step-name { color: var(--text); min-width: 10rem; }
    .step-summary { color: var(--muted); font-size: 0.8rem; }
    .status-running .step-icon::after { content: '⟳'; color: var(--amber); animation: spin 1s linear infinite; display: inline-block; }
    .status-done    .step-icon::after { content: '✓'; color: var(--green); }
    .status-failed  .step-icon::after { content: '✗'; color: var(--red); }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── report ── */
    #report-section { width: 100%; max-width: 700px; display: none; }
    #report-section h2 { color: var(--green); font-size: 0.8rem; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.75rem; }
    #report-body {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem 2rem;
      line-height: 1.7;
    }
    #report-body h2 {
      color: var(--green);
      font-size: 1rem;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.4rem;
      margin: 1.5rem 0 0.75rem;
      text-transform: none;
    }
    #report-body h2:first-child { margin-top: 0; }
    #report-body p  { margin-bottom: 0.75rem; color: var(--text); font-size: 0.9rem; }
    #report-body ul { margin: 0.5rem 0 0.75rem 1.2rem; }
    #report-body li { margin-bottom: 0.35rem; color: var(--text); font-size: 0.9rem; }
    #report-body strong { color: #e6edf3; }

    .badge-high   { background: #ff4444; color: #fff; padding: 1px 7px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .badge-medium { background: #ffaa00; color: #000; padding: 1px 7px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .badge-low    { background: #00ff88; color: #000; padding: 1px 7px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }

    /* ── action bar ── */
    #action-bar { display: none; gap: 0.75rem; margin-top: 1rem; flex-wrap: wrap; }
    .action-btn {
      padding: 0.6rem 1.2rem;
      border: 1px solid var(--green);
      background: transparent;
      color: var(--green);
      border-radius: 6px;
      font-family: var(--font);
      font-size: 0.85rem;
      cursor: pointer;
      transition: background 0.2s, color 0.2s;
    }
    .action-btn:hover { background: var(--green); color: #0d1117; }

    /* ── error banner ── */
    #error-banner {
      display: none;
      width: 100%;
      max-width: 700px;
      padding: 0.75rem 1rem;
      background: rgba(255,68,68,0.1);
      border: 1px solid var(--red);
      border-radius: 6px;
      color: var(--red);
      font-size: 0.85rem;
      margin-bottom: 1rem;
    }

    /* ── footer ── */
    footer {
      margin-top: auto;
      padding-top: 3rem;
      color: var(--muted);
      font-size: 0.75rem;
      text-align: center;
      max-width: 600px;
    }

    /* ── print / PDF ── */
    @media print {
      body { background: #fff; color: #000; padding: 1rem; }
      header h1 { color: #000; text-shadow: none; }
      #input-section, #progress-section, #action-bar, footer { display: none !important; }
      #report-section { display: block !important; }
      #report-body { border: none; padding: 0; }
      #report-body h2 { color: #000; border-bottom: 1px solid #ccc; }
      #report-body p, #report-body li { color: #000; }
      .badge-high   { background: #fcc; color: #000; }
      .badge-medium { background: #fec; color: #000; }
      .badge-low    { background: #cfc; color: #000; }
    }

    @media (max-width: 500px) {
      #scan-form { flex-direction: column; }
      .step-name { min-width: unset; }
    }
  </style>
</head>
<body>

  <header>
    <h1>HEIMDALL</h1>
    <p>Autonomous OSINT Intelligence Platform</p>
  </header>

  <section id="input-section">
    <form id="scan-form" onsubmit="startScan(event)">
      <input
        id="target-input"
        type="text"
        placeholder="company name or domain (e.g. google.com)"
        autocomplete="off"
        spellcheck="false"
        required
      />
      <button id="scan-btn" type="submit">Run Scan</button>
    </form>
  </section>

  <div id="error-banner"></div>

  <section id="progress-section">
    <h2>// Recon Progress</h2>
    <ul id="steps-list"></ul>
  </section>

  <section id="report-section">
    <h2>// Threat Intelligence Report</h2>
    <div id="report-body"></div>
    <div id="action-bar">
      <button class="action-btn" onclick="copyReport()">Copy Report</button>
      <button class="action-btn" onclick="window.print()">Download PDF</button>
      <button class="action-btn" onclick="newScan()">New Scan</button>
    </div>
  </section>

  <footer>
    Heimdall uses only publicly available data.<br />
    Use responsibly and only on domains you own or have permission to test.
  </footer>

  <script>
    const STEP_NAMES = [
      "Domain Resolution",
      "WHOIS Lookup",
      "DNS Enumeration",
      "Subdomain Discovery",
      "Tech Stack Detection",
      "Wayback Machine",
      "Robots & Sitemap",
      "Breach Check",
      "Generating Report",
    ];

    let activeSource = null;

    function showError(msg) {
      const banner = document.getElementById('error-banner');
      banner.textContent = msg;
      banner.style.display = 'block';
    }

    function hideError() {
      document.getElementById('error-banner').style.display = 'none';
    }

    function setScanning(active) {
      document.getElementById('scan-btn').disabled = active;
      document.getElementById('target-input').disabled = active;
    }

    function buildProgressRows() {
      const list = document.getElementById('steps-list');
      list.innerHTML = '';
      STEP_NAMES.forEach(name => {
        const li = document.createElement('li');
        li.className = 'step-row status-pending';
        li.id = `step-${name.replace(/\s+/g, '-')}`;
        li.innerHTML = `
          <span class="step-icon"></span>
          <span class="step-name">${name}</span>
          <span class="step-summary"></span>
        `;
        list.appendChild(li);
      });
    }

    function updateStep(name, status, summary) {
      const id = `step-${name.replace(/\s+/g, '-')}`;
      const row = document.getElementById(id);
      if (!row) return;
      row.className = `step-row status-${status}`;
      row.querySelector('.step-summary').textContent = summary || '';
    }

    async function startScan(e) {
      e.preventDefault();
      hideError();

      const input = document.getElementById('target-input').value.trim();
      if (!input) return;

      // Reset UI
      document.getElementById('report-section').style.display = 'none';
      document.getElementById('action-bar').style.display = 'none';
      document.getElementById('report-body').innerHTML = '';
      buildProgressRows();
      document.getElementById('progress-section').style.display = 'block';
      setScanning(true);

      if (activeSource) { activeSource.close(); activeSource = null; }

      let scanId;
      try {
        const resp = await fetch('/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input }),
        });
        const json = await resp.json();
        if (!resp.ok) { showError(json.error || 'Scan failed to start'); setScanning(false); return; }
        scanId = json.scan_id;
      } catch (err) {
        showError('Could not reach the server. Is Flask running?');
        setScanning(false);
        return;
      }

      activeSource = new EventSource(`/stream/${scanId}`);

      activeSource.addEventListener('step', e => {
        const d = JSON.parse(e.data);
        updateStep(d.name, d.status, d.summary);
      });

      activeSource.addEventListener('report', e => {
        const d = JSON.parse(e.data);
        document.getElementById('report-body').innerHTML = d.html;
        document.getElementById('report-section').style.display = 'block';
      });

      activeSource.addEventListener('done', () => {
        activeSource.close();
        activeSource = null;
        setScanning(false);
        document.getElementById('action-bar').style.display = 'flex';
      });

      activeSource.onerror = () => {
        activeSource.close();
        activeSource = null;
        setScanning(false);
        showError('Stream connection lost. The scan may have encountered an error.');
      };
    }

    function copyReport() {
      const html = document.getElementById('report-body').innerHTML;
      const text = document.getElementById('report-body').innerText;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      const btn = event.target;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy Report'; }, 1500);
    }

    function newScan() {
      document.getElementById('progress-section').style.display = 'none';
      document.getElementById('report-section').style.display = 'none';
      document.getElementById('action-bar').style.display = 'none';
      document.getElementById('report-body').innerHTML = '';
      document.getElementById('target-input').value = '';
      document.getElementById('target-input').focus();
      hideError();
      setScanning(false);
    }
  </script>

</body>
</html>
```

- [ ] **Step 2: Run all tests to verify nothing regressed**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest -v
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add templates/index.html
git commit -m "feat: complete frontend UI with SSE progress feed and report rendering"
```

---

## Task 8: Smoke Test + Final Verification

**Files:** No changes — manual verification only.

- [ ] **Step 1: Set the Anthropic API key**

```bash
export ANTHROPIC_API_KEY="your-key-here"
```

- [ ] **Step 2: Start the Flask server**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && python app.py
```

Expected output:
```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

- [ ] **Step 3: Open the app in a browser**

Navigate to `http://127.0.0.1:5000`

Verify:
- Dark terminal theme renders correctly
- Input field shows placeholder `company name or domain (e.g. google.com)`
- "Run Scan" button is enabled

- [ ] **Step 4: Run a domain scan**

Enter `github.com` and click Run Scan.

Verify:
- Submit button disables immediately
- All 9 step rows appear with spinner
- Steps complete one by one with green checkmarks and summaries
- Report section appears after Step 9 with formatted HTML
- Badge colours visible (High=red, Medium=amber, Low=green)
- "Copy Report", "Download PDF", "New Scan" buttons appear

- [ ] **Step 5: Test PDF download**

Click "Download PDF" — verify browser print dialog opens with clean white report layout (no dark background, no UI chrome).

- [ ] **Step 6: Test "New Scan" reset**

Click "New Scan" — verify UI resets to initial state with empty input field.

- [ ] **Step 7: Test URL input normalisation**

Enter `https://www.github.com/` — verify scan runs on `github.com` not the raw URL.

- [ ] **Step 8: Run full test suite one final time**

```bash
cd /home/dev-lahrani/Desktop/Projcts/HEIMDALL && pytest -v
```

Expected: all tests pass.

- [ ] **Step 9: Final commit**

```bash
git add -A
git commit -m "feat: Heimdall OSINT agent — complete implementation"
```

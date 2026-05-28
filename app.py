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

def normalise_input(raw: str) -> str:
    s = raw.strip().lower()
    s = re.sub(r'^https?://', '', s)
    s = re.sub(r'^www\.', '', s)
    s = s.rstrip('/')
    return s

def is_domain(s: str) -> bool:
    return '.' in s and ' ' not in s

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
        if not is_domain(domain):
            return {"status": "failed", "summary": f"Claude returned unexpected value: {domain!r}"}
        data['domain'] = domain
        return {"status": "done", "summary": f"Resolved: {domain}"}
    except Exception as e:
        return {"status": "failed", "summary": str(e)}


def _safe_date(val) -> str:
    if isinstance(val, list):
        return str(val[0]) if val else "Unknown"
    return str(val) if val else "Unknown"


def step_whois(domain: str, data: dict) -> dict:
    try:
        w = whois_lib.whois(domain)
        created = w.creation_date
        expiry = w.expiration_date
        data['whois'] = {
            "registrar": str(w.registrar or "Unknown"),
            "created": _safe_date(created),
            "expiry": _safe_date(expiry),
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
        if not any(records.values()):
            return {"status": "failed", "summary": "No DNS records resolved"}
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
            entry.strip()
            for e in resp.json()
            for entry in e.get('name_value', '').strip().lower().split('\n')
            if entry.strip() and '*' not in entry.strip()
        ))
        data['subdomains'] = subdomains
        return {"status": "done", "summary": f"{len(subdomains)} subdomain(s) found"}
    except Exception as e:
        data['subdomains'] = []
        return {"status": "failed", "summary": str(e)}


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


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

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

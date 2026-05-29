import uuid
import json
import os
import re
import datetime

from flask import Flask, request, jsonify, Response, render_template, stream_with_context
import whois as whois_lib
import dns.resolver
import requests as http
import anthropic
import bleach
import weasyprint

app = Flask(__name__)
scans = {}          # scan_id -> {"input": str, "data": dict}
scan_history = []   # recent scan summaries, max 5
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
        return str(val[0]) if (val and val[0] is not None) else "Unknown"
    return str(val) if val else "Unknown"


def step_whois(domain: str, data: dict) -> dict:
    try:
        w = whois_lib.whois(domain)
        data['whois'] = {
            "registrar": str(w.registrar or "Unknown"),
            "created": _safe_date(w.creation_date),
            "expiry": _safe_date(w.expiration_date),
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
            ("WordPress",          "wp-content" in html or "wp-includes" in html),
            ("Drupal",             "drupal" in html),
            ("Joomla",             "joomla" in html),
            ("React",              "react-dom" in html or "_react" in html),
            ("Vue.js",             "vue.js" in html or "__vue__" in html),
            ("Angular",            "ng-app" in html or "angular.min.js" in html),
            ("jQuery",             "jquery" in html),
            ("Bootstrap",          "bootstrap" in html),
            ("Tailwind CSS",       "tailwind" in html),
            ("Google Analytics",   "google-analytics.com" in html or "gtag(" in html),
            ("Google Tag Manager", "googletagmanager.com" in html),
            ("Cloudflare",         "cloudflare" in headers.get("server", "") or "cf-ray" in headers),
            ("nginx",              "nginx" in headers.get("server", "")),
            ("Apache",             "apache" in headers.get("server", "")),
            ("PHP",                "php" in headers.get("x-powered-by", "")),
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


def step_github_leaks(domain: str, data: dict) -> dict:
    try:
        resp = http.get(
            f"https://api.github.com/search/code?q={domain}&per_page=5",
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Heimdall-OSINT/1.0",
            },
            timeout=10,
        )
        if resp.status_code == 403:
            data['github'] = []
            data['github_total'] = 0
            return {"status": "done", "summary": "GitHub rate limit reached — skipped"}
        resp.raise_for_status()
        body = resp.json()
        total = body.get("total_count", 0)
        items = body.get("items", [])
        data['github'] = [
            {
                "repo": item["repository"]["full_name"],
                "file": item["path"],
                "url": item["html_url"],
            }
            for item in items
        ]
        data['github_total'] = total
        return {"status": "done", "summary": f"{total} code mention(s) found on GitHub"}
    except Exception as e:
        data['github'] = []
        data['github_total'] = 0
        return {"status": "failed", "summary": str(e)}


def step_virustotal(domain: str, data: dict) -> dict:
    vt_key = os.environ.get("VT_API_KEY")
    if not vt_key:
        data['virustotal'] = {}
        return {"status": "done", "summary": "VirusTotal skipped (no API key configured)"}
    try:
        resp = http.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": vt_key},
            timeout=10,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            data['virustotal'] = {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
            }
            return {"status": "done", "summary": f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless engines"}
        elif resp.status_code == 404:
            data['virustotal'] = {}
            return {"status": "done", "summary": "Domain not found in VirusTotal"}
        else:
            data['virustotal'] = {}
            return {"status": "done", "summary": f"VirusTotal returned {resp.status_code}"}
    except Exception as e:
        data['virustotal'] = {}
        return {"status": "failed", "summary": str(e)}


_ALLOWED_TAGS = ['h2', 'p', 'ul', 'li', 'strong', 'span']
_ALLOWED_ATTRS = {'span': ['class']}


def step_claude_report(domain: str, data: dict) -> dict:
    all_data_str = json.dumps(data, indent=2, default=str)
    try:
        resp = get_client().messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=(
                "You are a senior threat intelligence analyst. You write professional, "
                "structured OSINT reports for defensive security teams. "
                "Output ONLY valid HTML using <h2>, <p>, <ul>, <li>, <strong>, <span> tags. "
                "No markdown. No code blocks. No preamble. "
                "After the HTML, on a new line write exactly: RISK_SCORE: <integer 0-100>"
            ),
            messages=[{
                "role": "user",
                "content": (
                    f"Based on this raw OSINT data about {domain}, write a professional "
                    f"threat intelligence report with these exact sections:\n"
                    f"1. Executive Summary (3 sentences, non-technical)\n"
                    f"2. Digital Footprint Overview\n"
                    f"3. Exposed Attack Surface (subdomains, tech stack, open paths)\n"
                    f"4. GitHub Exposure (leaked credentials, exposed configs, code mentions)\n"
                    f"5. Breach & Leak History\n"
                    f"6. Key Risk Findings — rank each High / Medium / Low, wrap badge in "
                    f"<span class='badge-high'>, <span class='badge-medium'>, or <span class='badge-low'>\n"
                    f"7. Recommended Actions\n"
                    f"Raw data: {all_data_str}"
                ),
            }],
        )
        raw_text = resp.content[0].text.strip()

        score_match = re.search(r'RISK_SCORE:\s*(\d+)', raw_text)
        risk_score = min(100, max(0, int(score_match.group(1)))) if score_match else 50

        raw_html = re.sub(r'\s*RISK_SCORE:\s*\d+\s*$', '', raw_text, flags=re.MULTILINE).strip()
        html = bleach.clean(raw_html, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True)

        data['report_html'] = html
        data['risk_score'] = risk_score
        return {"status": "done", "summary": f"Threat intelligence report generated (risk score: {risk_score})"}
    except Exception as e:
        return {"status": "failed", "summary": str(e)}


def sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


_STEPS = [
    ("Domain Resolution",    step_resolve_domain),
    ("WHOIS Lookup",         step_whois),
    ("DNS Enumeration",      step_dns),
    ("Subdomain Discovery",  step_subdomains),
    ("Tech Stack Detection", step_tech_stack),
    ("Wayback Machine",      step_wayback),
    ("Robots & Sitemap",     step_robots_sitemap),
    ("Breach Check",         step_breach),
    ("GitHub Leaks",         step_github_leaks),
    ("VirusTotal Check",     step_virustotal),
    ("Generating Report",    step_claude_report),
]


def run_scan(scan_id: str, raw_input: str, data: dict):
    step_statuses = {}

    for name, fn in _STEPS:
        yield sse("step", {"name": name, "status": "running", "summary": ""})

        if fn is step_resolve_domain:
            result = fn(raw_input, data)
        elif fn is step_claude_report:
            data_steps = [s for f, s in step_statuses.items() if f is not step_resolve_domain]
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

        step_statuses[fn] = result["status"]
        yield sse("step", {"name": name, "status": result["status"], "summary": result["summary"]})

    report_html = data.get("report_html", "")
    if report_html:
        breach_data = data.get('breach', {})
        breach_status = "breached" if (breach_data.get('hibp') or breach_data.get('psbdmp')) else "clean"

        yield sse("report", {
            "html": report_html,
            "risk_score": data.get('risk_score', 50),
            "subdomain_count": len(data.get('subdomains', [])),
            "breach_status": breach_status,
            "tech_count": len(data.get('tech_stack', {}).get('detected', [])),
            "github_count": data.get('github_total', 0),
            "wayback_count": len(data.get('wayback', [])),
            "dns_count": sum(len(v) for v in data.get('dns', {}).values()),
        })

        scan_history.append({
            "scan_id": scan_id,
            "input": raw_input,
            "domain": data.get('domain', raw_input),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "risk_score": data.get('risk_score', 50),
        })
        if len(scan_history) > 5:
            scan_history.pop(0)

        if len(scans) > 10:
            oldest = next(iter(scans))
            del scans[oldest]

    yield sse("done", {})


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def start_scan():
    body = request.get_json(force=True, silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "input is required"}), 400
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
        yield from run_scan(scan_id, scan["input"], scan["data"])

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


@app.route('/history')
def get_history():
    return jsonify(list(reversed(scan_history)))


@app.route('/export/<scan_id>')
def export_pdf(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found or expired"}), 404
    report_html = scan['data'].get('report_html', '')
    if not report_html:
        return jsonify({"error": "no report available"}), 404
    domain = scan['data'].get('domain', 'unknown')
    full_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
body {{ font-family: Arial, sans-serif; color: #1a1a1a; max-width: 900px; margin: 0 auto; padding: 2rem; line-height: 1.6; }}
h1 {{ font-size: 1.8rem; border-bottom: 2px solid #1a1a1a; padding-bottom: 0.5rem; margin-bottom: 0.5rem; }}
.meta {{ color: #555; font-size: 0.9rem; margin-bottom: 2rem; }}
h2 {{ font-size: 1.1rem; color: #111; border-bottom: 1px solid #ccc; padding-bottom: 0.3rem; margin: 1.5rem 0 0.75rem; }}
p {{ margin-bottom: 0.75rem; }}
ul {{ margin: 0.5rem 0 0.75rem 1.5rem; }}
li {{ margin-bottom: 0.3rem; }}
strong {{ color: #000; }}
.badge-high   {{ background: #ff4444; color: #fff; padding: 1px 7px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
.badge-medium {{ background: #ffaa00; color: #000; padding: 1px 7px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
.badge-low    {{ background: #22c55e; color: #000; padding: 1px 7px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ccc; font-size: 0.75rem; color: #888; }}
</style>
</head>
<body>
<h1>HEIMDALL — Threat Intelligence Report</h1>
<div class="meta">Target: <strong>{domain}</strong></div>
{report_html}
<footer>Generated by Heimdall OSINT. Use responsibly and only on domains you own or have permission to test.</footer>
</body>
</html>"""
    try:
        pdf_bytes = weasyprint.HTML(string=full_html).write_pdf()
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="heimdall-{domain}.pdf"'},
        )
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", port=5000)

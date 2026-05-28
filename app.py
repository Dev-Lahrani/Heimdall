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


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

def run_scan(raw_input: str, data: dict):
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
